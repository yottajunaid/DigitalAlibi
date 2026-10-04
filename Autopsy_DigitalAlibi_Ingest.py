# -*- coding: utf-8 -*-
"""Digital Alibi Autopsy Data Source Ingest Module (Jython 2.7).

Installation
------------
Create an Autopsy Python module directory, for example::

    DigitalAlibi/
      Autopsy_DigitalAlibi_Ingest.py
      lib/sqlite-jdbc-<version>.jar
      lib/bcprov-<version>.jar
      lib/bcpkix-<version>.jar
      DigitalAlibi_TSA_Root.pem        # optional but strongly recommended

Autopsy loads JARs placed in a module's ``lib`` directory. The module extracts
SQLite and TSR content only into the active Autopsy case temp directory, never
back to the acquisition USB. It deletes its temporary extraction after parsing.

The module is deliberately conservative:
* a record is hash-valid only if canonical JSON, zlib level 9 compression, and
  SHA-256 reproduce the logged ``compressed_sha256``;
* an RFC 3161 token is not marked trusted merely because it has an embedded
  signer. Bouncy Castle is required to parse/validate CMS. A pinned TSA root
  certificate is required to mark chain validation as trusted;
* missing optional JARs yield explicit Blackboard comments rather than a false
  successful verification.
"""
from __future__ import print_function

import base64
import binascii
import hashlib
import json
import os
import zlib

from java.io import File
from java.io import ByteArrayOutputStream
from java.io import FileInputStream
from java.lang import Class
from java.security import KeyFactory
from java.security import Security
from java.security import Signature
from java.security.cert import CertificateFactory as JavaCertificateFactory
from java.security.cert import CertPathValidator as JavaCertPathValidator
from java.security.cert import PKIXParameters as JavaPKIXParameters
from java.security.cert import TrustAnchor as JavaTrustAnchor
from java.security.spec import X509EncodedKeySpec
from java.sql import DriverManager
from java.util import ArrayList
from java.util import HashSet
from java.util.logging import Level

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute


MODULE_NAME = "Digital Alibi Environmental Evidence"
MODULE_VERSION = "1.0.0"
DATABASE_NAME = "digital_alibi.sqlite"
SCHEMA_NAME = "digital-alibi.evidence/v1"
MAX_JSON_BYTES = 4 * 1024 * 1024


try:
    from org.bouncycastle.cms import CMSSignedData
    from org.bouncycastle.jce.provider import BouncyCastleProvider
    from org.bouncycastle.cms.jcajce import JcaSimpleSignerInfoVerifierBuilder
    from org.bouncycastle.cert.jcajce import JcaX509CertificateConverter
    from org.bouncycastle.tsp import TimeStampToken
    BC_AVAILABLE = True
except ImportError:
    BC_AVAILABLE = False


class DigitalAlibiIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and independently verifies Digital Alibi environmental evidence SQLite records and RFC 3161 tokens."

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return DigitalAlibiIngestModule()


class DigitalAlibiIngestModule(DataSourceIngestModule):
    def __init__(self):
        self.context = None
        self.logger = Logger.getLogger(MODULE_NAME)
        self.sqlite_available = False
        self.bc_available = BC_AVAILABLE

    def log(self, level, message):
        self.logger.logp(level, self.__class__.__name__, "process", message)

    def startUp(self, context):
        self.context = context
        try:
            Class.forName("org.sqlite.JDBC")
            self.sqlite_available = True
        except Exception as ex:
            # Do not fail all ingest. The investigator may still use the module
            # with a later-installed module-local sqlite-jdbc JAR.
            self.sqlite_available = False
            self.log(Level.WARNING, "sqlite-jdbc is unavailable: " + str(ex))
        if self.bc_available:
            try:
                Security.addProvider(BouncyCastleProvider())
            except Exception as ex:
                self.bc_available = False
                self.log(Level.WARNING, "Bouncy Castle could not be registered: " + str(ex))
        else:
            self.log(Level.WARNING, "Bouncy Castle unavailable. RFC 3161 CMS tokens will be reported as unverified.")

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        file_manager = Case.getCurrentCase().getServices().getFileManager()
        database_files = file_manager.findFiles(dataSource, DATABASE_NAME)
        total_records = 0
        errors = 0

        if not self.sqlite_available:
            self.post_message(
                IngestMessage.MessageType.ERROR,
                "Digital Alibi database found but no sqlite-jdbc driver is loaded. Add sqlite-jdbc JAR under the module lib directory and restart Autopsy."
                if len(database_files) else "No Digital Alibi database found.",
            )
            return IngestModule.ProcessResult.OK

        progressBar.switchToDeterminate(len(database_files))
        database_count = 0
        for database_file in database_files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            database_count += 1
            try:
                parsed_count = self.process_database(dataSource, database_file, file_manager)
                total_records += parsed_count
            except Exception as ex:
                errors += 1
                self.log(Level.SEVERE, "Failed processing " + database_file.getName() + ": " + str(ex))
                self.create_status_artifact(database_file, "Digital Alibi database could not be parsed: " + str(ex), "ERROR")
            progressBar.progress(database_count)

        if total_records:
            try:
                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(MODULE_NAME, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None)
                )
            except Exception as ex:
                self.log(Level.WARNING, "Unable to fire Blackboard event: " + str(ex))
        self.post_message(
            IngestMessage.MessageType.DATA,
            "Processed %d Digital Alibi capture record(s) from %d database(s); %d database error(s)." % (total_records, database_count, errors),
        )
        return IngestModule.ProcessResult.OK

    def process_database(self, data_source, database_file, file_manager):
        local_db = self.case_temp_file("digital_alibi_%d.sqlite" % database_file.getId())
        db_conn = None
        statement = None
        result_set = None
        count = 0
        try:
            ContentUtils.writeToFile(database_file, local_db)
            db_conn = DriverManager.getConnection("jdbc:sqlite:" + local_db.getAbsolutePath())
            statement = db_conn.createStatement()
            result_set = statement.executeQuery(
                "SELECT capture_id, captured_at_utc, payload_json, compressed_sha256, compressed_size, "
                "compressed_payload_b64, tsa_status, tsr_path, tsa_message_imprint, local_key_fingerprint, merkle_batch_id "
                "FROM captures ORDER BY created_at_utc"
            )
            batches = self.load_merkle_batches(db_conn)
            while result_set.next():
                if self.context.isJobCancelled():
                    break
                record = self.read_capture_record(result_set)
                hash_status = self.verify_capture_hash(record)
                local_status = self.verify_local_merkle(record, batches)
                tsr_status = self.verify_tsr(database_file, data_source, file_manager, record)
                comment = self.format_comment(record, hash_status, local_status, tsr_status)
                severity = "INFO" if self.is_clean(hash_status, tsr_status) else "WARNING"
                self.create_status_artifact(database_file, comment, severity)
                count += 1
        finally:
            self.close_quietly(result_set)
            self.close_quietly(statement)
            self.close_quietly(db_conn)
            if local_db.exists() and not local_db.delete():
                self.log(Level.WARNING, "Could not delete Autopsy case temporary file " + local_db.getAbsolutePath())
        return count

    def case_temp_file(self, name):
        case_temp = Case.getCurrentCase().getTempDirectory()
        return File(case_temp, name)

    def load_merkle_batches(self, connection):
        batches = {}
        statement = None
        result_set = None
        try:
            statement = connection.createStatement()
            result_set = statement.executeQuery(
                "SELECT batch_id, created_at_utc, leaf_count, merkle_root, leaf_hashes_json, "
                "signature_b64, public_key_b64, key_fingerprint FROM merkle_batches"
            )
            while result_set.next():
                batch_id = result_set.getString("batch_id")
                batches[batch_id] = {
                    "batch_id": batch_id,
                    "created_at_utc": result_set.getString("created_at_utc"),
                    "leaf_count": result_set.getInt("leaf_count"),
                    "merkle_root": result_set.getString("merkle_root"),
                    "leaf_hashes_json": result_set.getString("leaf_hashes_json"),
                    "signature_b64": result_set.getString("signature_b64"),
                    "public_key_b64": result_set.getString("public_key_b64"),
                    "key_fingerprint": result_set.getString("key_fingerprint"),
                }
        except Exception as ex:
            self.log(Level.WARNING, "Merkle batch table could not be queried: " + str(ex))
        finally:
            self.close_quietly(result_set)
            self.close_quietly(statement)
        return batches

    def read_capture_record(self, result_set):
        return {
            "capture_id": result_set.getString("capture_id"),
            "captured_at_utc": result_set.getString("captured_at_utc"),
            "payload_json": result_set.getString("payload_json"),
            "compressed_payload_b64": result_set.getString("compressed_payload_b64"),
            "compressed_sha256": result_set.getString("compressed_sha256"),
            "compressed_size": result_set.getLong("compressed_size"),
            "tsa_status": result_set.getString("tsa_status"),
            "tsr_path": result_set.getString("tsr_path"),
            "tsa_message_imprint": result_set.getString("tsa_message_imprint"),
            "local_key_fingerprint": result_set.getString("local_key_fingerprint"),
            "merkle_batch_id": result_set.getString("merkle_batch_id"),
        }

    def verify_capture_hash(self, record):
        payload_text = record["payload_json"]
        if payload_text is None:
            return (False, "HASH_INVALID: payload_json is NULL")
        if len(payload_text) > MAX_JSON_BYTES:
            return (False, "HASH_INVALID: payload_json exceeds safe size")
        try:
            payload = json.loads(payload_text)
            if payload.get("schema") != SCHEMA_NAME:
                return (False, "HASH_INVALID: unsupported or missing schema")
            canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            compressed = base64.b64decode(record["compressed_payload_b64"])
            digest = hashlib.sha256(compressed).hexdigest()
            if digest != record["compressed_sha256"]:
                return (False, "HASH_INVALID: compressed SHA-256 mismatch")
            if len(compressed) != record["compressed_size"]:
                return (False, "HASH_INVALID: compressed byte count mismatch")
            if zlib.decompress(compressed) != canonical:
                return (False, "HASH_INVALID: exact compressed payload does not decode to canonical JSON")
            if digest != record["tsa_message_imprint"]:
                return (False, "HASH_INVALID: TSA imprint does not match evidence digest")
            return (True, "HASH_VALID")
        except Exception as ex:
            return (False, "HASH_INVALID: " + str(ex))

    def merkle_root(self, leaf_hashes):
        if not leaf_hashes:
            raise ValueError("no Merkle leaves")
        level = [binascii.unhexlify(item) for item in sorted(leaf_hashes)]
        for item in level:
            if len(item) != 32:
                raise ValueError("non-SHA-256 Merkle leaf")
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            next_level = []
            for index in range(0, len(level), 2):
                next_level.append(hashlib.sha256(level[index] + level[index + 1]).digest())
            level = next_level
        return binascii.hexlify(level[0])

    def bytes_to_hex(self, values):
        return "".join(["%02x" % (item & 0xff) for item in values])

    def verify_local_merkle(self, record, batches):
        batch_id = record["merkle_batch_id"]
        if not batch_id:
            return "LOCAL_NOT_APPLICABLE"
        if batch_id not in batches:
            return "LOCAL_INVALID: referenced Merkle batch absent"
        batch = batches[batch_id]
        try:
            leaves = json.loads(batch["leaf_hashes_json"])
            if record["compressed_sha256"] not in leaves:
                return "LOCAL_INVALID: capture digest is absent from batch leaves"
            computed_root = self.merkle_root(leaves)
            if computed_root != batch["merkle_root"]:
                return "LOCAL_INVALID: Merkle root mismatch"
            if len(leaves) != batch["leaf_count"]:
                return "LOCAL_INVALID: leaf count mismatch"
            envelope = {
                "purpose": "digital-alibi.merkle-root/v1",
                "batch_id": batch["batch_id"],
                "created_at_utc": batch["created_at_utc"],
                "leaf_count": batch["leaf_count"],
                "merkle_root": batch["merkle_root"],
            }
            canonical = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            public_key_bytes = base64.b64decode(batch["public_key_b64"])
            signature_bytes = base64.b64decode(batch["signature_b64"])
            if hashlib.sha256(public_key_bytes).hexdigest() != batch["key_fingerprint"]:
                return "LOCAL_INVALID: public-key fingerprint mismatch"
            try:
                public_key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(public_key_bytes))
                verifier = Signature.getInstance("Ed25519")
                verifier.initVerify(public_key)
                verifier.update(canonical)
                if not verifier.verify(signature_bytes):
                    return "LOCAL_INVALID: Ed25519 signature mismatch"
            except Exception as ex:
                return "LOCAL_UNVERIFIED: Ed25519 unavailable in this Autopsy JRE (" + str(ex) + ")"
            return "LOCAL_VALID: Ed25519 signature and Merkle root verified"
        except Exception as ex:
            return "LOCAL_INVALID: " + str(ex)

    def normalise_case_path(self, value):
        return str(value).replace("\\", "/").rstrip("/") + "/"

    def select_tsr_candidate(self, database_file, candidates, record):
        relative_path = record["tsr_path"].replace("\\", "/")
        parent_parts = relative_path.rsplit("/", 1)
        tsr_parent = parent_parts[0] + "/" if len(parent_parts) == 2 else ""
        expected_parent = self.normalise_case_path(database_file.getParentPath()) + tsr_parent
        exact_matches = []
        for candidate in candidates:
            if self.normalise_case_path(candidate.getParentPath()) == expected_parent:
                exact_matches.append(candidate)
        if len(exact_matches) == 1:
            return exact_matches[0]
        if len(exact_matches) > 1:
            raise ValueError("multiple TSR files match the capture path")
        raise ValueError("referenced TSR path does not match database directory")

    def verify_tsr(self, database_file, data_source, file_manager, record):
        if record["tsa_status"] != "TSA_SEALED":
            return "TSA_NOT_SEALED: status=" + str(record["tsa_status"])
        if not record["tsr_path"]:
            return "TSA_INVALID: TSA_SEALED record has no TSR path"
        if not self.bc_available:
            return "TSA_UNVERIFIED: Bouncy Castle CMS/TSP library unavailable"
        tsr_name = File(record["tsr_path"]).getName()
        candidates = file_manager.findFiles(data_source, tsr_name)
        if not candidates:
            return "TSA_INVALID: referenced TSR file not found (" + tsr_name + ")"
        local_tsr = self.case_temp_file("digital_alibi_tsr_%s" % tsr_name)
        try:
            candidate = self.select_tsr_candidate(database_file, candidates, record)
            ContentUtils.writeToFile(candidate, local_tsr)
            token_bytes = self.read_bytes(local_tsr)
            token = TimeStampToken(CMSSignedData(token_bytes))
            imprint = self.bytes_to_hex(token.getTimeStampInfo().getMessageImprintDigest())
            if imprint != record["tsa_message_imprint"]:
                return "TSA_INVALID: RFC 3161 message imprint mismatch"
            certificate_store = token.getCertificates()
            matches = certificate_store.getMatches(token.getSID())
            iterator = matches.iterator()
            if not iterator.hasNext():
                return "TSA_INVALID: signer certificate missing from token"
            signer_holder = iterator.next()
            verifier = JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signer_holder)
            token.validate(verifier)
            trust = self.validate_tsa_chain(certificate_store, signer_holder, token.getTimeStampInfo().getGenTime())
            return "TSA_SIGNATURE_VALID: RFC 3161 imprint and CMS signature verified; " + trust
        except Exception as ex:
            return "TSA_INVALID: " + str(ex)
        finally:
            if local_tsr.exists() and not local_tsr.delete():
                self.log(Level.WARNING, "Could not delete temporary TSR " + local_tsr.getAbsolutePath())

    def validate_tsa_chain(self, certificate_store, signer_holder, generation_time):
        root_path = File(os.path.dirname(os.path.abspath(__file__)), "DigitalAlibi_TSA_Root.pem")
        if not root_path.isFile():
            return "CHAIN_UNTRUSTED: no pinned DigitalAlibi_TSA_Root.pem"
        stream = None
        try:
            stream = FileInputStream(root_path)
            certificate_factory = JavaCertificateFactory.getInstance("X.509")
            root_certificate = certificate_factory.generateCertificate(stream)
            converter = JcaX509CertificateConverter().setProvider("BC")
            signer_certificate = converter.getCertificate(signer_holder)
            path_certificates = ArrayList()
            holders = certificate_store.getMatches(None).iterator()
            while holders.hasNext():
                certificate = converter.getCertificate(holders.next())
                if not certificate.equals(root_certificate):
                    path_certificates.add(certificate)
            cert_path = certificate_factory.generateCertPath(path_certificates)
            trust_anchors = HashSet()
            trust_anchors.add(JavaTrustAnchor(root_certificate, None))
            parameters = JavaPKIXParameters(trust_anchors)
            parameters.setRevocationEnabled(False)
            JavaCertPathValidator.getInstance("PKIX").validate(cert_path, parameters)
            return "CHAIN_TRUSTED: pinned root validated (revocation checking disabled by module)"
        except Exception as ex:
            return "CHAIN_UNTRUSTED: pinned-root validation failed (" + str(ex) + ")"
        finally:
            self.close_quietly(stream)

    def read_bytes(self, file_object):
        stream = None
        try:
            stream = FileInputStream(file_object)
            output = ByteArrayOutputStream()
            import jarray
            buffer = jarray.zeros(8192, "b")
            read_count = stream.read(buffer)
            while read_count != -1:
                output.write(buffer, 0, read_count)
                read_count = stream.read(buffer)
            return output.toByteArray()
        finally:
            self.close_quietly(stream)
            self.close_quietly(output if 'output' in locals() else None)

    def is_clean(self, hash_status, tsr_status):
        return hash_status[0] and tsr_status.startswith("TSA_SIGNATURE_VALID")

    def format_comment(self, record, hash_status, local_status, tsr_status):
        return (
            "Digital Alibi capture\n"
            "capture_id: %s\n"
            "captured_at_utc: %s\n"
            "evidence_sha256: %s\n"
            "tsa_status: %s\n"
            "hash_verification: %s\n"
            "local_merkle: %s\n"
            "rfc3161: %s"
            % (
                record["capture_id"],
                record["captured_at_utc"],
                record["compressed_sha256"],
                record["tsa_status"],
                hash_status[1],
                local_status,
                tsr_status,
            )
        )

    def create_status_artifact(self, source_file, comment, severity):
        try:
            attributes = ArrayList()
            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, "Digital Alibi"))
            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, MODULE_NAME, comment))
            artifact = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            artifact.addAttributes(attributes)
            blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            blackboard.postArtifact(artifact, MODULE_NAME, self.context.getJobId())
        except Exception as ex:
            self.log(Level.SEVERE, "Unable to create Blackboard artifact (" + severity + "): " + str(ex))

    def close_quietly(self, value):
        if value is None:
            return
        try:
            value.close()
        except Exception:
            pass

    def post_message(self, message_type, message):
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(message_type, MODULE_NAME, message))
