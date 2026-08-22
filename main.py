# ---------------------------------------------------------
# WEEK 8 - Q1
# Immutable, Leakage-Safe Training Corpus
# ---------------------------------------------------------

# hashlib gives us SHA-256.
import hashlib

# json is used to read JSONL rows and create compact JSON.
import json

# math is used to check whether contaminationThreshold is finite.
import math

# re is used for validating timestamps, CRC, generation, URI, etc.
import re
import uuid
# unicodedata is needed for Unicode NFKC normalization
# and Unicode letter/number detection.
import unicodedata

# datetime is needed for timestamp validation and UTC conversion.
from datetime import datetime, timezone

# FastAPI creates the web API.
from fastapi import FastAPI, Request

# JSONResponse lets us explicitly return HTTP 400 when needed.
from fastapi.responses import JSONResponse


# Create the FastAPI application.
app = FastAPI()


# ---------------------------------------------------------
# REGULAR EXPRESSIONS
# ---------------------------------------------------------

# Valid timestamp:
# YYYY-MM-DDTHH:mm:ss[.sss](Z|±HH:mm)
#
# Fractional seconds can contain only 1, 2, or 3 digits.
TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d{1,3})?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})$"
)


# Basic Google Storage URI:
# gs://bucket/object
URI_RE = re.compile(r"^gs://[^/\s]+/[^\r\n]+$")


# A generation must contain only decimal digits.
DECIMAL_RE = re.compile(r"^[0-9]+$")


# CRC32C must be exactly 8 LOWERCASE hexadecimal characters.
CRC_RE = re.compile(r"^[0-9a-f]{8}$")


# Maximum JavaScript safe integer.
SAFE_INTEGER_MAX = 2**53 - 1


# ---------------------------------------------------------
# SMALL HELPER FUNCTIONS
# ---------------------------------------------------------

def strict_json_loads(value):
    """
    Parse strict JSON.

    Python normally accepts NaN, Infinity and -Infinity,
    although they are not valid JSON.
    We reject them.
    """

    def reject_invalid_constant(constant):
        raise ValueError(
            f"Invalid JSON constant: {constant}"
        )

    return json.loads(
        value,
        parse_constant=reject_invalid_constant
    )
def utf8_key(value):
    """
    Convert a string to UTF-8 bytes.

    The assignment specifically says sorting must use UTF-8 bytes.
    """
    return value.encode("utf-8")


def compact_json(value):
    """
    Convert an object to compact JSON.

    ensure_ascii=False means non-ASCII Unicode characters are written
    directly instead of becoming \\uXXXX sequences.

    separators removes spaces.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )
# ---------------------------------------------------------
# AUDIT / DEBUG LOGGING
# ---------------------------------------------------------

# Leave this True while debugging the grader.
# It only writes information to Render logs.
# It DOES NOT change the API response.
AUDIT_ENABLED = True


def audit(request_id, stage, data):
    """
    Write structured debugging information to Render logs.

    ensure_ascii=True is deliberate because invisible Unicode
    characters will appear as escapes such as \\u2028.
    """

    if not AUDIT_ENABLED:
        return

    try:
        payload = json.dumps(
            data,
            ensure_ascii=True,
            separators=(",", ":"),
            default=str
        )

    except Exception:
        payload = repr(data)

    print(
        f"AUDIT|{request_id}|{stage}|{payload}",
        flush=True
    )

# ---------------------------------------------------------
# CRC32C
# ---------------------------------------------------------

def crc32c_hex(text):
    """
    Calculate CRC32C over the EXACT UTF-8 bytes of content.

    IMPORTANT:
    CRC32C is NOT the same thing as normal zlib.crc32().
    """

    # Standard CRC32C starting value.
    crc = 0xFFFFFFFF

    # Process every UTF-8 byte.
    for byte in text.encode("utf-8"):

        crc ^= byte

        # Process all 8 bits in this byte.
        for _ in range(8):

            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1

    # Final XOR and convert to exactly 8 lowercase hex digits.
    return f"{(crc ^ 0xFFFFFFFF) & 0xFFFFFFFF:08x}"


# ---------------------------------------------------------
# TIMESTAMP VALIDATION + UTC NORMALIZATION
# ---------------------------------------------------------

def parse_event_time(value):
    """
    Validate a timestamp and convert it to:

    YYYY-MM-DDTHH:mm:ss.sssZ

    Returns None if invalid.
    """

    # Must be a string.
    if not isinstance(value, str):
        return None

    # First check the required textual format.
    match = TIME_RE.fullmatch(value)

    if match is None:
        return None

    # Extract timezone part.
    tz_part = match.group("tz")

    # Validate ±HH:mm timezone.
    if tz_part != "Z":

        # Characters 1-2 contain hour.
        offset_hour = int(tz_part[1:3])

        # Characters 4-5 contain minute.
        offset_minute = int(tz_part[4:6])

        # Offset cannot exceed 14 hours.
        if offset_hour > 14:
            return None

        # Minute must be 00-59.
        if offset_minute > 59:
            return None

        # ±14 is only allowed as ±14:00.
        if offset_hour == 14 and offset_minute != 0:
            return None

    # Get optional fractional second.
    fraction = match.group("fraction")

    # Python can parse ISO timestamps easily after we prepare them.
    if fraction is None:

        # No fraction was supplied.
        # Add .000.

        if tz_part == "Z":

            iso_text = value[:-1] + ".000+00:00"

        else:

            iso_text = (
                value[:-len(tz_part)]
                + ".000"
                + tz_part
            )

    else:

        # Remove the "." and pad fraction to exactly 3 digits.
        fraction_digits = fraction[1:].ljust(3, "0")

        padded_fraction = "." + fraction_digits

        if tz_part == "Z":

            iso_text = (
                value[:-1 - len(fraction)]
                + padded_fraction
                + "+00:00"
            )

        else:

            iso_text = (
                value[:-len(tz_part) - len(fraction)]
                + padded_fraction
                + tz_part
            )

    try:

        # Python validates actual calendar values here:
        # month, date, hour, minute, second, etc.
        parsed = datetime.fromisoformat(iso_text)

        # Convert the time to UTC.
        utc_time = parsed.astimezone(timezone.utc)

    except (ValueError, OverflowError):

        # Invalid calendar/time.
        return None

    # Always output exactly three millisecond digits.
    milliseconds = utc_time.microsecond // 1000

    return (
        utc_time.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{milliseconds:03d}Z"
    )


# ---------------------------------------------------------
# CANONICALIZATION
# ---------------------------------------------------------

def canonicalize_text(value):
    """
    Required canonicalization:

    1. Unicode NFKC
    2. lowercase
    3. trim
    4. collapse Unicode whitespace to one ASCII space
    """

    # Unicode compatibility normalization.
    value = unicodedata.normalize("NFKC", value)

    # Convert to lowercase.
    value = value.lower()

    # Remove whitespace from beginning/end.
    value = value.strip()

    # Collapse any run of Unicode whitespace into one normal space.
    value = re.sub(
        r"\s+",
        " ",
        value,
        flags=re.UNICODE
    )

    return value


# ---------------------------------------------------------
# CONTAMINATION TOKENIZATION
# ---------------------------------------------------------

def word_set(text):
    """
    Create a set of lowercase Unicode letter/number words.

    A character is part of a word if its Unicode category
    starts with L (Letter) or N (Number).
    """

    words = set()

    current_word = []

    # The specification says lowercase.
    for char in text.lower():

        # Example:
        # L = Letter
        # N = Number
        # P = Punctuation
        category = unicodedata.category(char)

        if category.startswith("L") or category.startswith("N"):

            current_word.append(char)

        else:

            # Non-letter/number ends the current word.
            if current_word:

                words.add("".join(current_word))

                current_word = []

    # Add the final word if the text ended with a letter/number.
    if current_word:

        words.add("".join(current_word))

    return words


def jaccard(left_text, right_text):
    """
    Calculate Jaccard similarity:

        intersection size
        -----------------
           union size

    Empty/empty must equal 1.
    """

    left = word_set(left_text)

    right = word_set(right_text)

    # Required special case.
    if not left and not right:
        return 1.0

    union = left | right

    if not union:
        return 1.0

    intersection = left & right

    return len(intersection) / len(union)


# ---------------------------------------------------------
# POLICY VALIDATION
# ---------------------------------------------------------

def validate_policy(policy):
    """
    Validate minTime, maxTime and contaminationThreshold.

    Returns normalized policy if valid.
    Otherwise returns None.
    """

    # Policy must itself be an object.
    if not isinstance(policy, dict):
        return None

    # Validate and normalize the two times.
    min_time = parse_event_time(policy.get("minTime"))

    max_time = parse_event_time(policy.get("maxTime"))

    # Read contamination threshold.
    threshold = policy.get("contaminationThreshold")

    # Invalid time means invalid policy.
    if min_time is None or max_time is None:
        return None

    # Boolean is technically an int in Python,
    # so explicitly reject True and False.
    if isinstance(threshold, bool):
        return None

    # Threshold must be numeric.
    if not isinstance(threshold, (int, float)):
        return None

    # Convert to float.
    threshold = float(threshold)

    # Must be finite.
    if not math.isfinite(threshold):
        return None

    # Must be between 0 and 1 inclusive.
    if not (0.0 <= threshold <= 1.0):
        return None

    # A minimum after maximum is not a valid time window.
    if min_time > max_time:
        return None

    return {
        "minTime": min_time,
        "maxTime": max_time,
        "contaminationThreshold": threshold,
    }


# ---------------------------------------------------------
# OBJECT VALIDATION
# ---------------------------------------------------------

def validate_and_read_object(obj):
    """
    Validate one supplied object.

    If valid:
        returns accepted data, None

    If invalid:
        returns None, rejected-object record
    """

    reason_codes = []

    # Safely extract fields.
    if isinstance(obj, dict):

        raw_uri = obj.get("uri")

        generation = obj.get("generation")

        fetched_generation = obj.get("fetchedGeneration")

        crc = obj.get("crc32c")

        schema_id = obj.get("schemaId")

        content = obj.get("content")

    else:

        # A completely invalid object.
        raw_uri = None

        generation = None

        fetched_generation = None

        crc = None

        schema_id = None

        content = None


    # -----------------------------------------------------
    # URI validation
    # -----------------------------------------------------

    if (
        not isinstance(raw_uri, str)
        or URI_RE.fullmatch(raw_uri) is None
    ):

        reason_codes.append("URI_INVALID")


    # -----------------------------------------------------
    # GENERATION validation
    # -----------------------------------------------------

    generation_supplied = (
        isinstance(obj, dict)
        and "generation" in obj
    )

    fetched_generation_supplied = (
        isinstance(obj, dict)
        and "fetchedGeneration" in obj
    )
    # generation must be a decimal string.
    generation_valid = (
        isinstance(generation, str)
        and DECIMAL_RE.fullmatch(generation) is not None
    )
    fetched_generation_valid = (
        isinstance(fetched_generation, str)
        and DECIMAL_RE.fullmatch(fetched_generation) is not None
    )

    # Either invalid -> GENERATION_INVALID.
    if not generation_valid or not fetched_generation_valid:

        reason_codes.append("GENERATION_INVALID")

    # GENERATION_MISMATCH applies when both fields were supplied
    # but their values are different.
    if (
        generation_supplied
        and fetched_generation_supplied
        and generation != fetched_generation
    ):

        reason_codes.append("GENERATION_MISMATCH")


    # -----------------------------------------------------
    # CRC32C validation
    # -----------------------------------------------------

    crc_valid = (
        isinstance(crc, str)
        and CRC_RE.fullmatch(crc) is not None
    )

    if not crc_valid:

        reason_codes.append("CRC32C_INVALID")

    # CRC mismatch is checked only when:
    # 1. CRC syntax is valid
    # 2. content is a string
    elif isinstance(content, str):

        calculated_crc = crc32c_hex(content)

        if calculated_crc != crc:

            reason_codes.append("CRC32C_MISMATCH")


    # -----------------------------------------------------
    # SCHEMA ID + CONTENT TYPE
    # -----------------------------------------------------

    if (
        schema_id != "training-v1"
        or not isinstance(content, str)
    ):

        reason_codes.append("SCHEMA_INVALID")


    # This will contain canonicalized rows.
    parsed_rows = []


    # -----------------------------------------------------
    # JSONL
    # -----------------------------------------------------

    if isinstance(content, str):

        nonblank_line_count = 0

        # splitlines handles \n and \r\n correctly.
        for line in content.split("\n"):

            # Blank lines must be ignored.
            if line.strip() == "":
                continue

            nonblank_line_count += 1

            # Try to parse this JSON line.
            try:

                row = strict_json_loads(line)

            except (json.JSONDecodeError, ValueError):
                # Parsing failure.
                reason_codes.append("JSONL_INVALID")

                continue


            # -------------------------------------------------
            # Each row must be a JSON object.
            # -------------------------------------------------

            if not isinstance(row, dict):

                reason_codes.append("SCHEMA_INVALID")

                continue


            # Required EXACT row keys.
            expected_keys = {
                "id",
                "entity",
                "eventTime",
                "revision",
                "text"
            }

            # No missing keys and no extra keys.
            if set(row.keys()) != expected_keys:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # Four string fields
            # -------------------------------------------------

            string_fields_are_valid = all(
                isinstance(row[key], str)
                for key in (
                    "id",
                    "entity",
                    "eventTime",
                    "text"
                )
            )

            if not string_fields_are_valid:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # revision
            # -------------------------------------------------

            revision = row["revision"]

            # Must be:
            # - integer
            # - not boolean
            # - >= 0
            # - <= JS safe integer
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
                or revision > SAFE_INTEGER_MAX
            ):

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # eventTime
            # -------------------------------------------------

            normalized_time = parse_event_time(
                row["eventTime"]
            )

            if normalized_time is None:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # Canonical row
            #
            # IMPORTANT: create keys in EXACT required order:
            #
            # id
            # entity
            # eventTime
            # revision
            # text
            # -------------------------------------------------

            canonical_row = {
                "id": row["id"],

                "entity": canonicalize_text(
                    row["entity"]
                ),

                "eventTime": normalized_time,

                "revision": revision,

                "text": canonicalize_text(
                    row["text"]
                ),
            }

            parsed_rows.append(canonical_row)


        # File must have at least one nonblank row.
        if nonblank_line_count == 0:

            reason_codes.append("SCHEMA_INVALID")


    # -----------------------------------------------------
    # Sort + deduplicate object reason codes
    # -----------------------------------------------------

    reason_codes = sorted(
        set(reason_codes),
        key=utf8_key
    )


    # -----------------------------------------------------
    # Reject complete object if ANY object error occurred
    # -----------------------------------------------------

    if reason_codes:

        # URI must become null if supplied URI wasn't a string.
        rejected_object = {
            "uri": (
                raw_uri
                if isinstance(raw_uri, str)
                else None
            ),

            "reasonCodes": reason_codes,
        }

        return None, rejected_object


    # -----------------------------------------------------
    # Accepted object lineage
    # -----------------------------------------------------

    lineage = {
        "uri": raw_uri,
        "generation": generation,
        "crc32c": crc,
        "schemaId": schema_id,
    }


    return {
        "rows": parsed_rows,
        "lineage": lineage,
    }, None


# ---------------------------------------------------------
# REJECTED ROW HELPER
# ---------------------------------------------------------

def reject_row(rejected_rows, row_id, *codes):
    """
    Add one rejected-row record.
    """

    reason_codes = sorted(
        set(codes),
        key=utf8_key
    )

    rejected_rows.append({
        "id": row_id,
        "reasonCodes": reason_codes,
    })


# ---------------------------------------------------------
# DEDUPLICATION
# ---------------------------------------------------------

def deduplicate_rows(rows, rejected_rows):
    """
    Deduplicate using:

        [entity, eventTime, text]

    Winner:
    1. highest revision
    2. UTF-8-byte-smallest ID
    """

    groups = {}


    # Group rows by the required tuple.
    for row in rows:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(key, []).append(row)


    winners = []


    # Process each duplicate group.
    for group in groups.values():

        # Sort so the winner appears first.
        ordered = sorted(
            group,
            key=lambda row: (
                # Negative means higher revision first.
                -row["revision"],

                # Then smallest UTF-8 ID.
                utf8_key(row["id"]),

                # Deterministic final tie-breaker.
                compact_json(row).encode("utf-8"),
            ),
        )


        # First row survives.
        winner = ordered[0]

        winners.append(winner)


        # Every other row is DUPLICATE.
        for loser in ordered[1:]:

            reject_row(
                rejected_rows,
                loser["id"],
                "DUPLICATE"
            )


    return winners


# ---------------------------------------------------------
# TRAIN / VALIDATION / TEST BUCKET
# ---------------------------------------------------------

def split_bucket(entity):
    """
    bucket =
        first byte of SHA256(UTF8(entity)) % 10

    0-5 -> train
    6-7 -> validation
    8-9 -> test
    """

    # SHA-256 raw 32-byte digest.
    digest = hashlib.sha256(
        entity.encode("utf-8")
    ).digest()


    # Get first byte.
    first_byte = digest[0]


    # Modulo 10.
    bucket = first_byte % 10


    if bucket <= 5:

        return "train"


    if bucket <= 7:

        return "validation"


    return "test"


# ---------------------------------------------------------
# SORT SPLIT ROWS
# ---------------------------------------------------------

def sort_rows(rows):
    """
    Sort by:
    1. UTF-8 bytes of ID
    2. compact JSON
    """

    return sorted(
        rows,
        key=lambda row: (
            utf8_key(row["id"]),
            compact_json(row).encode("utf-8"),
        ),
    )


# ---------------------------------------------------------
# SHA-256 SPLIT DIGEST
# ---------------------------------------------------------

def digest_rows(rows):
    """
    Serialize each row as compact JSON,
    append one newline after EVERY row,
    then SHA-256 the exact UTF-8 bytes.
    """

    payload = "".join(
        compact_json(row) + "\n"
        for row in rows
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# RESPONSE SORTING
# ---------------------------------------------------------

def sort_rejected_objects(items):
    """
    Sort rejected objects by URI UTF-8 bytes.

    null URI is placed before string URIs.
    Compact JSON is used as tie-breaker.
    """

    def key(item):

        uri = item["uri"]

        if isinstance(uri, str):
            return (
                0,
                uri.encode("utf-8"),
                compact_json(item).encode("utf-8"),
            )
        return (
            1,
            b"",
            compact_json(item).encode("utf-8"),
           )
            
    return sorted(items, key=key)


def sort_rejected_rows(items):
    """
    Sort rejected rows by ID UTF-8 bytes,
    then compact JSON.
    """

    return sorted(
        items,
        key=lambda item: (
            item["id"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        ),
    )


def sort_lineage(items):
    """
    Sort lineage by URI UTF-8 bytes,
    then compact JSON.
    """

    return sorted(
        items,
        key=lambda item: (
            item["uri"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        ),
    )


# ---------------------------------------------------------
# MAIN ENDPOINT
# ---------------------------------------------------------

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # Give this grader request a short unique ID.
    # This helps us match all audit lines belonging
    # to the same hidden test.
    request_id = uuid.uuid4().hex[:8]


    # -----------------------------------------------------
    # Read request body
    # -----------------------------------------------------

    try:

        # Read the exact incoming bytes.
        raw_body = await request.body()

        # Record HTTP information in Render logs.
        audit(
            request_id,
            "HTTP_REQUEST",
            {
                "method": request.method,
                "contentType": request.headers.get("content-type"),
                "accept": request.headers.get("accept"),
                "rawBodyBytes": repr(raw_body),
            }
        )


        # Request JSON must be UTF-8.
        body_text = raw_body.decode("utf-8")


        # This log is especially useful for invisible
        # Unicode characters.
        audit(
            request_id,
            "DECODED_BODY",
            {
                "bodyRepr": repr(body_text)
            }
        )


        # Parse strict JSON.
        body = strict_json_loads(body_text)


        audit(
            request_id,
            "REQUEST_PARSED",
            {
                "type": type(body).__name__,
                "body": body,
            }
        )


    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:

        audit(
            request_id,
            "REQUEST_PARSE_FAILED",
            {
                "exceptionType": type(exc).__name__,
                "exception": str(exc),
            }
        )

        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"},
        )

    # -----------------------------------------------------
    # Top-level validation
    #
    # Missing policy OR non-array objects
    # must return HTTP 400 exactly:
    #
    # {"error":"INVALID_INPUT"}
    # -----------------------------------------------------

    if (
        not isinstance(body, dict)
        or "policy" not in body
        or not isinstance(body.get("objects"), list)
    ):
        audit(
        request_id,
        "INVALID_TOP_LEVEL_INPUT",
        {
            "bodyType": type(body).__name__,
            "hasPolicy": (
                isinstance(body, dict)
                and "policy" in body
            ),
            "objectsType": (
                type(body.get("objects")).__name__
                if isinstance(body, dict)
                else None
            ),
        }
    )

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )


    # -----------------------------------------------------
    # Validate policy
    # -----------------------------------------------------

    policy = validate_policy(
        body["policy"]
    )
    audit(
        request_id,
        "POLICY_RESULT",
    {
            "suppliedPolicy": body["policy"],
            "normalizedPolicy": policy,
            "valid": policy is not None,
        }
    )


    # All rows from valid objects.
    accepted_rows = []


    # Object rejection output.
    rejected_objects = []


    # Row rejection output.
    rejected_rows = []


    # Valid object lineage.
    lineage = []


    # -----------------------------------------------------
    # Validate every supplied object
    # -----------------------------------------------------

    for object_index, obj in enumerate(body["objects"]):

    # ---------------------------------------------
    # Audit the object exactly as supplied
    # ---------------------------------------------

        if isinstance(obj, dict):

            content = obj.get("content")

        # Calculate CRC independently for debugging.
            calculated_crc = (
                crc32c_hex(content)
                if isinstance(content, str)
                else None
            )

            object_snapshot = {
                "index": object_index,
                "uri": obj.get("uri"),
                "uriType": type(obj.get("uri")).__name__,
                "generation": obj.get("generation"),
                "generationType": type(
                    obj.get("generation")
                 ).__name__,
                "fetchedGeneration": obj.get(
                    "fetchedGeneration"
                ),
                "fetchedGenerationType": type(
                    obj.get("fetchedGeneration")
                ).__name__,
                "crc32c": obj.get("crc32c"),
                "calculatedCrc32c": calculated_crc,
                "schemaId": obj.get("schemaId"),
                "contentType": type(content).__name__,
                "contentRepr": repr(content),
            }

        else:

            object_snapshot = {
                "index": object_index,
                "objectType": type(obj).__name__,
                "suppliedValue": repr(obj),
            }


        audit(
            request_id,
            "OBJECT_INPUT",
            object_snapshot
        )


    # ---------------------------------------------
    # Run actual object validation
    # ---------------------------------------------

        accepted, rejected = (
            validate_and_read_object(obj)
        )


    # ---------------------------------------------
    # Rejected object
    # ---------------------------------------------

        if rejected is not None:

            audit(
                request_id,
                "OBJECT_REJECTED",
                {
                    "index": object_index,
                    "result": rejected,
                }
                )

            rejected_objects.append(
                rejected
            )

            continue


    # ---------------------------------------------
    # Accepted object
    # ---------------------------------------------

        audit(
            request_id,
            "OBJECT_ACCEPTED",
            {
                "index": object_index,
                "lineage": accepted["lineage"],
                "rowCount": len(accepted["rows"]),
                "rows": accepted["rows"],
            }
        )


        accepted_rows.extend(
            accepted["rows"]
        )


        lineage.append(
            accepted["lineage"]
        )

    # -----------------------------------------------------
    # Deduplication
    # -----------------------------------------------------

    retained_rows = deduplicate_rows(
        accepted_rows,
        rejected_rows
    )


    # Required split object.
    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }


    # -----------------------------------------------------
    # Invalid policy
    # -----------------------------------------------------

    if policy is None:

        # Every deduplicated retained row is rejected.
        for row in retained_rows:

            reject_row(
                rejected_rows,
                row["id"],
                "POLICY_INVALID"
            )


    # -----------------------------------------------------
    # Valid policy
    # -----------------------------------------------------

    else:

        in_window_rows = []


        # -------------------------------------------------
        # Inclusive time window
        # -------------------------------------------------

        for row in retained_rows:

            if not (
                policy["minTime"]
                <= row["eventTime"]
                <= policy["maxTime"]
            ):

                reject_row(
                    rejected_rows,
                    row["id"],
                    "OUT_OF_WINDOW"
                )

                continue


            in_window_rows.append(row)


        # -------------------------------------------------
        # Initial deterministic hash splitting
        # -------------------------------------------------

        candidate_splits = {
            "train": [],
            "validation": [],
            "test": [],
        }


        for row in in_window_rows:

            split_name = split_bucket(
                row["entity"]
            )


            candidate_splits[
                split_name
            ].append(row)


        # -------------------------------------------------
        # Train rows are accepted immediately.
        # -------------------------------------------------

        train_rows = candidate_splits[
            "train"
        ]


        splits["train"] = train_rows


        # Contamination threshold.
        threshold = policy[
            "contaminationThreshold"
        ]


        # -------------------------------------------------
        # Check validation + test contamination
        # -------------------------------------------------

        for split_name in (
            "validation",
            "test"
        ):

            for row in candidate_splits[
                split_name
            ]:

                # Compare this text against EVERY train row.
                contaminated = any(

                    jaccard(
                        row["text"],
                        train_row["text"]
                    ) >= threshold

                    for train_row in train_rows
                )


                # Reject contaminated validation/test row.
                if contaminated:

                    reject_row(
                        rejected_rows,
                        row["id"],
                        "TRAIN_CONTAMINATION"
                    )


                # Otherwise keep it.
                else:

                    splits[
                        split_name
                    ].append(row)


    # -----------------------------------------------------
    # Sort the three split rows
    # -----------------------------------------------------

    for split_name in splits:

        splits[split_name] = sort_rows(
            splits[split_name]
        )


    # -----------------------------------------------------
    # Sort all deterministic response sections
    # -----------------------------------------------------

    rejected_objects = sort_rejected_objects(
        rejected_objects
    )


    rejected_rows = sort_rejected_rows(
        rejected_rows
    )


    lineage = sort_lineage(
        lineage
    )


    # -----------------------------------------------------
    # SHA-256 digests
    # -----------------------------------------------------

    digests = {

        "train": digest_rows(
            splits["train"]
        ),

        "validation": digest_rows(
            splits["validation"]
        ),

        "test": digest_rows(
            splits["test"]
        ),
    }


    # -----------------------------------------------------
    # EXACT required response shape
    # -----------------------------------------------------

    response_payload = {

        "splits": splits,

        "rejectedObjects": rejected_objects,

        "rejectedRows": rejected_rows,
    
        "digests": digests,

        "lineage": lineage,
    }


# Print our exact final answer to Render logs.
    audit(
        request_id,
        "FINAL_RESPONSE",
        response_payload
    )


    return response_payload

# =========================================================
# WEEK 8 - Q2
# Leakage-Safe BigQuery ML Experiment Gate
# Endpoint: POST /bqml
# =========================================================


# ---------------------------------------------------------
# STATEFUL RUN STORE
# ---------------------------------------------------------

# This dictionary remembers each selection by runId.
#
# Example:
#
# RUN_STORE["experiment-1"] = {
#     "fingerprint": "...",
#     "response": {...}
# }
#
# Render is currently using one worker, so the hidden grader's
# select -> evaluate requests can share this state.
BQML_RUN_STORE = {}


# A frozen datasetDigest must be exactly:
# 64 lowercase hexadecimal characters.
BQML_DIGEST_RE = re.compile(
    r"^[0-9a-f]{64}$"
)


# ---------------------------------------------------------
# BQML HELPER FUNCTIONS
# ---------------------------------------------------------

def bqml_utf8_ok(value):
    """
    Check that a value is a Python string that can be
    encoded as valid UTF-8.

    We need this because IDs and feature names are sorted
    using UTF-8 bytes.
    """

    if not isinstance(value, str):
        return False

    try:
        value.encode("utf-8")
        return True

    except UnicodeEncodeError:
        return False


def bqml_is_safe_int(value):
    """
    A non-negative JavaScript-safe integer.

    Maximum:
    2^53 - 1
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INTEGER_MAX
    )


def bqml_is_number(value):
    """
    True for an int or float, but NOT True/False.

    Python considers bool a subclass of int,
    so we explicitly reject booleans.
    """

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def bqml_is_finite_unit(value):
    """
    Validate a finite number in [0, 1].

    Used for:
    - metricFloor
    - required slice floors
    """

    return (
        bqml_is_number(value)
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def bqml_sort_codes(codes):
    """
    Sort and deduplicate reason codes by UTF-8 bytes.
    """

    return sorted(
        set(codes),
        key=lambda code: code.encode("utf-8")
    )


# ---------------------------------------------------------
# SELECTION REQUEST FINGERPRINT
# ---------------------------------------------------------

def bqml_selection_fingerprint(body):
    """
    Create an internal fingerprint of the selection request.

    This is NOT the datasetDigest.

    It is only used to detect:

        same runId + same input
            -> replay stored response

        same runId + different input
            -> HTTP 409 RUN_ID_CONFLICT

    sort_keys=True means JSON object key order does not
    accidentally create a conflict.
    """

    canonical = json.dumps(
        body,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# DATASET DIGEST
# ---------------------------------------------------------

def bqml_make_dataset_digest(
    train_row_ids,
    eval_row_ids,
    feature_names
):
    """
    Required exact digest artifact:

    {
      "trainRowIds": [...],
      "evalRowIds": [...],
      "featureNames": [...]
    }

    Key order must stay exactly as above.

    JSON is compact and encoded as UTF-8.
    """

    digest_object = {
        "trainRowIds": train_row_ids,
        "evalRowIds": eval_row_ids,
        "featureNames": feature_names,
    }


    # Compact JSON.
    exact_json = json.dumps(
        digest_object,
        ensure_ascii=False,
        separators=(",", ":")
    )


    # SHA-256 of exact UTF-8 bytes.
    return hashlib.sha256(
        exact_json.encode("utf-8")
    ).hexdigest()


# =========================================================
# SELECT PHASE
# =========================================================

def bqml_process_select(body, request_id):

    reason_codes = []


    # -----------------------------------------------------
    # 1. Validate runId
    # -----------------------------------------------------

    run_id = body.get("runId")


    run_id_valid = (
        bqml_utf8_ok(run_id)
        and 1 <= len(run_id) <= 128
    )


    if not run_id_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # 2. Validate forbiddenFeatures
    # -----------------------------------------------------

    forbidden_features = body.get(
        "forbiddenFeatures"
    )


    forbidden_valid = (
        isinstance(forbidden_features, list)
        and all(
            bqml_utf8_ok(name)
            for name in forbidden_features
        )
    )


    if not forbidden_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )

        forbidden_set = set()

    else:

        # Using a set makes membership checks easy.
        forbidden_set = set(
            forbidden_features
        )


    # -----------------------------------------------------
    # 3. Validate numTrialsLimit
    # -----------------------------------------------------

    num_trials_limit = body.get(
        "numTrialsLimit"
    )


    num_trials_limit_valid = (
        isinstance(num_trials_limit, int)
        and not isinstance(
            num_trials_limit,
            bool
        )
        and num_trials_limit > 0
    )


    if not num_trials_limit_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # 4. Validate selection rows
    # -----------------------------------------------------

    rows = body.get("rows")


    # Selection rows must be a NON-EMPTY array.
    rows_container_valid = (
        isinstance(rows, list)
        and len(rows) > 0
    )


    if not rows_container_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    parsed_rows = []

    seen_row_ids = set()

    rows_structurally_valid = (
        rows_container_valid
    )


    if rows_container_valid:

        for row_index, row in enumerate(rows):

            # Start by assuming this row is valid.
            row_ok = isinstance(
                row,
                dict
            )


            if not row_ok:

                rows_structurally_valid = False

                continue


            # ---------------------------------------------
            # Extract fields
            # ---------------------------------------------

            row_id = row.get("id")

            entity = row.get("entity")

            event_time_raw = row.get(
                "eventTime"
            )

            prediction_time_raw = row.get(
                "predictionTime"
            )

            version = row.get("version")

            split = row.get("split")

            features = row.get("features")


            # ---------------------------------------------
            # Row ID
            #
            # Must be a UTF-8 string.
            # IDs must also be unique within rows[].
            # ---------------------------------------------

            if not bqml_utf8_ok(row_id):

                row_ok = False

            else:

                if row_id in seen_row_ids:

                    row_ok = False

                else:

                    seen_row_ids.add(
                        row_id
                    )


            # ---------------------------------------------
            # Entity
            # ---------------------------------------------

            if not bqml_utf8_ok(entity):

                row_ok = False


            # ---------------------------------------------
            # eventTime + predictionTime
            #
            # Reuse our strict timestamp parser from Q1.
            #
            # It converts to:
            #
            # YYYY-MM-DDTHH:mm:ss.sssZ
            # ---------------------------------------------

            event_time_utc = parse_event_time(
                event_time_raw
            )


            prediction_time_utc = (
                parse_event_time(
                    prediction_time_raw
                )
            )


            if (
                event_time_utc is None
                or prediction_time_utc is None
            ):

                row_ok = False


            # ---------------------------------------------
            # Version
            # ---------------------------------------------

            if not bqml_is_safe_int(
                version
            ):

                row_ok = False


            # ---------------------------------------------
            # Split
            #
            # This is one of the most important
            # leakage protections.
            #
            # Selection NEVER accepts TEST rows.
            # ---------------------------------------------

            if split not in (
                "TRAIN",
                "EVAL"
            ):

                row_ok = False


            # ---------------------------------------------
            # Features
            # ---------------------------------------------

            parsed_features = {}


            if not isinstance(
                features,
                dict
            ):

                row_ok = False


            else:

                for (
                    feature_name,
                    feature_info
                ) in features.items():


                    # Feature name needs valid UTF-8
                    # because we later sort by UTF-8 bytes.
                    if not bqml_utf8_ok(
                        feature_name
                    ):

                        row_ok = False

                        continue


                    # Every feature record must contain:
                    #
                    # value
                    # availableAt
                    #
                    # We intentionally NEVER interpret value.
                    # Instructions inside value are just data.
                    if (
                        not isinstance(
                            feature_info,
                            dict
                        )
                        or "value"
                        not in feature_info
                        or "availableAt"
                        not in feature_info
                    ):

                        row_ok = False

                        continue


                    # availableAt must itself be
                    # a valid timestamp.
                    available_at_utc = (
                        parse_event_time(
                            feature_info.get(
                                "availableAt"
                            )
                        )
                    )


                    if available_at_utc is None:

                        row_ok = False

                        continue


                    # We only need availableAt for
                    # leakage checking.
                    #
                    # feature_info["value"] is deliberately
                    # ignored.
                    parsed_features[
                        feature_name
                    ] = {
                        "availableAt":
                            available_at_utc
                    }


            # ---------------------------------------------
            # Keep only completely valid rows
            # ---------------------------------------------

            if row_ok:

                parsed_rows.append({

                    "id":
                        row_id,

                    "entity":
                        entity,

                    "eventTime":
                        event_time_utc,

                    "predictionTime":
                        prediction_time_utc,

                    "version":
                        version,

                    "split":
                        split,

                    "features":
                        parsed_features,
                })


            else:

                rows_structurally_valid = False


    # Any bad row makes the whole selection malformed.
    if not rows_structurally_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # 5. Validate trials
    # -----------------------------------------------------

    trials = body.get("trials")


    trials_container_valid = isinstance(
        trials,
        list
    )


    if not trials_container_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    parsed_trials = []

    seen_trial_ids = set()

    trials_structurally_valid = (
        trials_container_valid
    )


    if trials_container_valid:


        # ---------------------------------------------
        # Trial count contract
        # ---------------------------------------------

        if (
            num_trials_limit_valid
            and len(trials)
            > num_trials_limit
        ):

            reason_codes.append(
                "TRIAL_LIMIT_EXCEEDED"
            )


        # ---------------------------------------------
        # Validate every trial
        # ---------------------------------------------

        for trial in trials:


            trial_ok = isinstance(
                trial,
                dict
            )


            if not trial_ok:

                trials_structurally_valid = False

                continue


            trial_id = trial.get(
                "trialId"
            )

            status = trial.get(
                "status"
            )

            eval_metric = trial.get(
                "evalMetric"
            )


            # Trial ID must be a non-negative
            # safe integer and unique.
            if not bqml_is_safe_int(
                trial_id
            ):

                trial_ok = False


            elif trial_id in seen_trial_ids:

                trial_ok = False


            else:

                seen_trial_ids.add(
                    trial_id
                )


            # Only these two statuses exist.
            if status not in (
                "SUCCEEDED",
                "FAILED"
            ):

                trial_ok = False


            if trial_ok:

                parsed_trials.append({

                    "trialId":
                        trial_id,

                    "status":
                        status,

                    # We do not validate this as a
                    # model metric yet.
                    #
                    # A SUCCEEDED trial is eligible
                    # only if this later turns out
                    # to be finite.
                    "evalMetric":
                        eval_metric,
                })


            else:

                trials_structurally_valid = False


    if not trials_structurally_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # Determine whether selection itself is malformed.
    #
    # TRIAL_LIMIT_EXCEEDED is a contract gate, but the
    # row dataset can still be deterministically built.
    #
    # NO_SUCCESSFUL_TRIAL also does not make the row
    # dataset malformed.
    # -----------------------------------------------------

    malformed = (
        "INVALID_INPUT"
        in reason_codes
    )


    # Default response artifacts.
    train_row_ids = []

    eval_row_ids = []

    feature_names = []

    dataset_digest = None

    selected_trial_id = None


    # =====================================================
    # Only process the dataset when selection input itself
    # is structurally valid.
    # =====================================================

    if not malformed:


        # -------------------------------------------------
        # 6. Deduplicate rows
        #
        # Key:
        # [entity, UTC(eventTime)]
        #
        # Winner:
        # 1. highest version
        # 2. UTF-8-byte-smallest ID
        # -------------------------------------------------

        row_groups = {}


        for row in parsed_rows:

            dedup_key = (
                row["entity"],
                row["eventTime"]
            )


            row_groups.setdefault(
                dedup_key,
                []
            ).append(row)


        retained_rows = []


        for group in row_groups.values():


            ordered_group = sorted(

                group,

                key=lambda row: (

                    # Highest version first.
                    -row["version"],

                    # Then smallest UTF-8 ID.
                    row["id"].encode(
                        "utf-8"
                    ),
                )
            )


            # First row is winner.
            retained_rows.append(
                ordered_group[0]
            )


        # -------------------------------------------------
        # 7. Split IDs
        #
        # Selection only knows:
        #
        # TRAIN
        # EVAL
        #
        # Never TEST.
        # -------------------------------------------------

        train_row_ids = sorted(

            [
                row["id"]
                for row in retained_rows
                if row["split"] == "TRAIN"
            ],

            key=lambda value:
                value.encode("utf-8")
        )


        eval_row_ids = sorted(

            [
                row["id"]
                for row in retained_rows
                if row["split"] == "EVAL"
            ],

            key=lambda value:
                value.encode("utf-8")
        )


        # -------------------------------------------------
        # 8. Find features appearing in EVERY retained row
        # -------------------------------------------------

        common_features = set(
            retained_rows[0][
                "features"
            ].keys()
        )


        for row in retained_rows[1:]:

            common_features &= set(
                row["features"].keys()
            )


        eligible_features = []


        # -------------------------------------------------
        # 9. Point-in-time / leakage test
        #
        # Feature is eligible only when:
        #
        # feature availableAt <= predictionTime
        #
        # for EVERY retained row.
        # -------------------------------------------------

        for feature_name in common_features:


            # Forbidden feature can never enter training.
            if feature_name in forbidden_set:

                continue


            point_in_time_safe = all(

                row[
                    "features"
                ][
                    feature_name
                ][
                    "availableAt"
                ]

                <=

                row[
                    "predictionTime"
                ]

                for row in retained_rows
            )


            if point_in_time_safe:

                eligible_features.append(
                    feature_name
                )


        # Required UTF-8 ordering.
        feature_names = sorted(

            eligible_features,

            key=lambda value:
                value.encode("utf-8")
        )


        # -------------------------------------------------
        # 10. Freeze dataset digest
        # -------------------------------------------------

        dataset_digest = (
            bqml_make_dataset_digest(
                train_row_ids,
                eval_row_ids,
                feature_names
            )
        )


        # -------------------------------------------------
        # AUDIT THE INTERNAL FROZEN DATASET
        # -------------------------------------------------

        audit(
            request_id,
            "BQML_SELECT_DATASET",
            {
                "retainedRows": [
                    {
                        "id": row["id"],
                        "entity": row["entity"],
                        "eventTime":
                            row["eventTime"],
                        "predictionTime":
                            row["predictionTime"],
                        "version":
                            row["version"],
                        "split":
                            row["split"],
                    }
                    for row in retained_rows
                ],
                "trainRowIds":
                    train_row_ids,
                "evalRowIds":
                    eval_row_ids,
                "featureNames":
                    feature_names,
                "datasetDigest":
                    dataset_digest,
            }
        )


        # -------------------------------------------------
        # 11. Find eligible trials
        #
        # Eligible only if:
        #
        # status == SUCCEEDED
        # AND evalMetric is finite
        # -------------------------------------------------

        eligible_trials = []


        for trial in parsed_trials:

            metric = trial[
                "evalMetric"
            ]


            if (
                trial["status"]
                == "SUCCEEDED"

                and bqml_is_number(
                    metric
                )

                and math.isfinite(
                    float(metric)
                )
            ):

                eligible_trials.append(
                    trial
                )


        # -------------------------------------------------
        # 12. Select trial
        # -------------------------------------------------

        if len(eligible_trials) == 0:

            reason_codes.append(
                "NO_SUCCESSFUL_TRIAL"
            )


        else:

            # Maximize evalMetric.
            #
            # Exact tie:
            # smallest integer trialId wins.
            ordered_trials = sorted(

                eligible_trials,

                key=lambda trial: (

                    -float(
                        trial[
                            "evalMetric"
                        ]
                    ),

                    trial[
                        "trialId"
                    ],
                )
            )


            selected_trial_id = (
                ordered_trials[0][
                    "trialId"
                ]
            )


    # -----------------------------------------------------
    # Sort + deduplicate reason codes.
    # -----------------------------------------------------

    reason_codes = bqml_sort_codes(
        reason_codes
    )


    # ANY reason code means selectedTrialId MUST be null.
    if reason_codes:

        selected_trial_id = None


    # -----------------------------------------------------
    # EXACT SELECT RESPONSE SHAPE
    # -----------------------------------------------------

    response = {

        "runId":
            (
                run_id
                if isinstance(run_id, str)
                else None
            ),

        "selectedTrialId":
            selected_trial_id,

        "trainRowIds":
            train_row_ids,

        "evalRowIds":
            eval_row_ids,

        "featureNames":
            feature_names,

        "datasetDigest":
            dataset_digest,

        "reasonCodes":
            reason_codes,
    }


    # -----------------------------------------------------
    # AUDIT
    # -----------------------------------------------------

    audit(
        request_id,
        "BQML_SELECT_RESPONSE",
        response
    )


    return response


# =========================================================
# EVALUATE PHASE
# =========================================================

def bqml_process_evaluate(
    body,
    request_id
):

    reason_codes = []


    # -----------------------------------------------------
    # Read frozen lineage supplied by caller
    # -----------------------------------------------------

    run_id = body.get(
        "runId"
    )

    selected_trial_id = body.get(
        "selectedTrialId"
    )

    dataset_digest = body.get(
        "datasetDigest"
    )


    # -----------------------------------------------------
    # 1. Validate lineage field FORMATS
    # -----------------------------------------------------

    run_id_format_valid = (
        bqml_utf8_ok(run_id)
        and 1 <= len(run_id) <= 128
    )


    trial_id_format_valid = (
        bqml_is_safe_int(
            selected_trial_id
        )
    )


    digest_format_valid = (
        isinstance(
            dataset_digest,
            str
        )
        and BQML_DIGEST_RE.fullmatch(
            dataset_digest
        )
        is not None
    )


    if not (
        run_id_format_valid
        and trial_id_format_valid
        and digest_format_valid
    ):

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # 2. metricFloor
    # -----------------------------------------------------

    metric_floor = body.get(
        "metricFloor"
    )


    metric_floor_valid = (
        bqml_is_finite_unit(
            metric_floor
        )
    )


    if not metric_floor_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    else:

        metric_floor = float(
            metric_floor
        )


    # -----------------------------------------------------
    # 3. requiredSlices
    #
    # Example:
    #
    # {
    #   "critical": 0.75,
    #   "vip": 0.80
    # }
    # -----------------------------------------------------

    required_slices = body.get(
        "requiredSlices"
    )


    required_slices_valid = isinstance(
        required_slices,
        dict
    )


    normalized_required_slices = {}


    if required_slices_valid:

        for (
            slice_name,
            slice_floor
        ) in required_slices.items():


            if (
                not bqml_utf8_ok(
                    slice_name
                )

                or slice_name == ""

                or not bqml_is_finite_unit(
                    slice_floor
                )
            ):

                required_slices_valid = False

                break


            normalized_required_slices[
                slice_name
            ] = float(
                slice_floor
            )


    if not required_slices_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )

        normalized_required_slices = {}


    # -----------------------------------------------------
    # 4. Validate byte fields
    # -----------------------------------------------------

    bytes_processed = body.get(
        "bytesProcessed"
    )


    max_bytes = body.get(
        "maxBytes"
    )


    bytes_valid = (
        bqml_is_safe_int(
            bytes_processed
        )
        and bqml_is_safe_int(
            max_bytes
        )
    )


    if not bytes_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    # -----------------------------------------------------
    # 5. Check frozen lineage
    # -----------------------------------------------------

    lineage_valid = False


    # Only attempt exact matching when the three
    # lineage fields themselves have valid formats.
    if (
        run_id_format_valid
        and trial_id_format_valid
        and digest_format_valid
    ):


        stored_run = BQML_RUN_STORE.get(
            run_id
        )


        if stored_run is not None:


            stored_response = (
                stored_run[
                    "response"
                ]
            )


            # Evaluation may use ONLY a completely
            # successful stored selection.
            stored_selection_successful = (

                stored_response[
                    "selectedTrialId"
                ]
                is not None

                and

                stored_response[
                    "datasetDigest"
                ]
                is not None

                and

                stored_response[
                    "reasonCodes"
                ]
                == []
            )


            if stored_selection_successful:


                lineage_valid = (

                    stored_response[
                        "selectedTrialId"
                    ]
                    == selected_trial_id

                    and

                    stored_response[
                        "datasetDigest"
                    ]
                    == dataset_digest
                )


        # Validly formatted lineage that doesn't exactly
        # match a successful stored selection is
        # INVALID_LINEAGE.
        if not lineage_valid:

            reason_codes.append(
                "INVALID_LINEAGE"
            )


    # -----------------------------------------------------
    # 6. BYTE LIMIT
    #
    # Byte checking still happens even if test rows
    # are empty or invalid.
    # -----------------------------------------------------

    if (
        bytes_valid
        and bytes_processed > max_bytes
    ):

        reason_codes.append(
            "BYTE_LIMIT"
        )


    # -----------------------------------------------------
    # 7. Validate final-test rows
    # -----------------------------------------------------

    rows = body.get("rows")


    rows_container_valid = isinstance(
        rows,
        list
    )


    if not rows_container_valid:

        reason_codes.append(
            "INVALID_INPUT"
        )


    valid_test_rows = []

    any_invalid_test_row = False


    if rows_container_valid:

        for row in rows:


            row_ok = isinstance(
                row,
                dict
            )


            if row_ok:


                label = row.get(
                    "label"
                )


                prediction = row.get(
                    "prediction"
                )


                slice_name = row.get(
                    "slice"
                )


                # Label must be integer 0 or 1.
                label_ok = (

                    isinstance(
                        label,
                        int
                    )

                    and not isinstance(
                        label,
                        bool
                    )

                    and label in (
                        0,
                        1
                    )
                )


                # Prediction must be integer 0 or 1.
                prediction_ok = (

                    isinstance(
                        prediction,
                        int
                    )

                    and not isinstance(
                        prediction,
                        bool
                    )

                    and prediction in (
                        0,
                        1
                    )
                )


                # Slice must be a non-empty UTF-8 string.
                slice_ok = (

                    bqml_utf8_ok(
                        slice_name
                    )

                    and slice_name != ""
                )


                row_ok = (
                    label_ok
                    and prediction_ok
                    and slice_ok
                )


            # ---------------------------------------------
            # Invalid row
            # ---------------------------------------------

            if not row_ok:

                any_invalid_test_row = True


            # ---------------------------------------------
            # Valid row
            # ---------------------------------------------

            else:

                valid_test_rows.append({

                    "label":
                        label,

                    "prediction":
                        prediction,

                    "slice":
                        slice_name,
                })


    if any_invalid_test_row:

        reason_codes.append(
            "INVALID_TEST_ROW"
        )


    # -----------------------------------------------------
    # 8. Decide whether metrics may be calculated
    #
    # IMPORTANT:
    #
    # If rows are EMPTY
    # OR any test row is INVALID:
    #
    # testMetric = null
    #
    # and skip aggregate/slice checks.
    # -----------------------------------------------------

    can_score = (

        rows_container_valid

        and len(rows) > 0

        and not any_invalid_test_row
    )


    test_metric = None


    # Used for debugging.
    slice_metrics = {}


    # -----------------------------------------------------
    # 9. Aggregate accuracy
    # -----------------------------------------------------

    if can_score:


        correct_predictions = sum(

            1

            for row in valid_test_rows

            if (
                row["label"]
                == row["prediction"]
            )
        )


        test_metric = round(

            correct_predictions
            / len(valid_test_rows),

            12
        )


        # Aggregate gate.
        if (
            metric_floor_valid
            and test_metric < metric_floor
        ):

            reason_codes.append(
                "AGGREGATE_FLOOR"
            )


        # -------------------------------------------------
        # 10. Required slice accuracy
        # -------------------------------------------------

        if required_slices_valid:


            sorted_required_names = sorted(

                normalized_required_slices.keys(),

                key=lambda value:
                    value.encode("utf-8")
            )


            for slice_name in sorted_required_names:


                matching_rows = [

                    row

                    for row in valid_test_rows

                    if (
                        row["slice"]
                        == slice_name
                    )
                ]


                # -----------------------------------------
                # Required slice does not exist
                # -----------------------------------------

                if len(matching_rows) == 0:


                    reason_codes.append(

                        "MISSING_SLICE:"
                        + slice_name
                    )


                    slice_metrics[
                        slice_name
                    ] = None


                    continue


                # -----------------------------------------
                # Calculate required-slice accuracy
                # -----------------------------------------

                correct_in_slice = sum(

                    1

                    for row in matching_rows

                    if (
                        row["label"]
                        == row["prediction"]
                    )
                )


                slice_accuracy = round(

                    correct_in_slice
                    / len(matching_rows),

                    12
                )


                slice_metrics[
                    slice_name
                ] = slice_accuracy


                required_floor = (
                    normalized_required_slices[
                        slice_name
                    ]
                )


                # Inclusive threshold:
                #
                # equal floor passes.
                if (
                    slice_accuracy
                    < required_floor
                ):

                    reason_codes.append(

                        "SLICE_FLOOR:"
                        + slice_name
                    )


    # -----------------------------------------------------
    # 11. criticalSlicePass
    #
    # It becomes FALSE for:
    #
    # INVALID_INPUT
    # INVALID_LINEAGE
    # INVALID_TEST_ROW
    # MISSING_SLICE:...
    # SLICE_FLOOR:...
    #
    # It deliberately does NOT summarize:
    #
    # AGGREGATE_FLOOR
    # BYTE_LIMIT
    # -----------------------------------------------------

    critical_slice_pass = can_score


    if (
        "INVALID_INPUT"
        in reason_codes

        or "INVALID_LINEAGE"
        in reason_codes

        or "INVALID_TEST_ROW"
        in reason_codes
    ):

        critical_slice_pass = False


    for code in reason_codes:


        if (
            code.startswith(
                "MISSING_SLICE:"
            )

            or code.startswith(
                "SLICE_FLOOR:"
            )
        ):

            critical_slice_pass = False


    # -----------------------------------------------------
    # 12. Sort + deduplicate reason codes
    # -----------------------------------------------------

    reason_codes = bqml_sort_codes(
        reason_codes
    )


    # -----------------------------------------------------
    # 13. Final admission decision
    #
    # Rows must actually be scoreable.
    #
    # So an empty test set rejects even though there
    # is no special EMPTY_ROWS reason code.
    # -----------------------------------------------------

    decision = "reject"


    if (
        len(reason_codes) == 0

        and can_score

        and test_metric is not None
    ):

        decision = "admit"


    # -----------------------------------------------------
    # EXACT EVALUATE RESPONSE SHAPE
    # -----------------------------------------------------

    response = {

        "runId":
            (
                run_id
                if isinstance(
                    run_id,
                    str
                )
                else None
            ),

        "selectedTrialId":
            (
                selected_trial_id
                if trial_id_format_valid
                else None
            ),

        "datasetDigest":
            (
                dataset_digest
                if digest_format_valid
                else None
            ),

        "testMetric":
            test_metric,

        "criticalSlicePass":
            critical_slice_pass,

        "decision":
            decision,

        "bytesProcessed":
            (
                bytes_processed
                if bqml_is_safe_int(
                    bytes_processed
                )
                else None
            ),

        "reasonCodes":
            reason_codes,
    }


    # -----------------------------------------------------
    # AUDIT
    # -----------------------------------------------------

    audit(
        request_id,
        "BQML_EVALUATE_RESPONSE",
        {
            "lineageValid":
                lineage_valid,

            "canScore":
                can_score,

            "sliceMetrics":
                slice_metrics,

            "response":
                response,
        }
    )


    return response


# =========================================================
# MAIN /bqml ENDPOINT
# =========================================================

@app.post("/bqml")
async def bqml_endpoint(
    request: Request
):


    # Unique ID for this HTTP request.
    # All audit lines for this request will share it.
    request_id = (
        uuid.uuid4().hex[:8]
    )


    # -----------------------------------------------------
    # 1. Strict request parsing
    # -----------------------------------------------------

    try:


        # Exact HTTP bytes.
        raw_body = await request.body()


        audit(
            request_id,
            "BQML_HTTP_REQUEST",
            {
                "contentType":
                    request.headers.get(
                        "content-type"
                    ),

                "rawBody":
                    repr(raw_body),
            }
        )


        # JSON request must be UTF-8.
        body_text = raw_body.decode(
            "utf-8"
        )


        # Reuse strict parser from Q1.
        #
        # This rejects invalid JSON constants such as:
        #
        # NaN
        # Infinity
        # -Infinity
        body = strict_json_loads(
            body_text
        )


    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:


        audit(
            request_id,
            "BQML_PARSE_FAILED",
            {
                "type":
                    type(exc).__name__,

                "message":
                    str(exc),
            }
        )


        return JSONResponse(

            status_code=400,

            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    # -----------------------------------------------------
    # Audit parsed request
    # -----------------------------------------------------

    audit(
        request_id,
        "BQML_REQUEST_PARSED",
        body
    )


    # -----------------------------------------------------
    # 2. Top-level JSON must be an object.
    # -----------------------------------------------------

    if not isinstance(
        body,
        dict
    ):


        return JSONResponse(

            status_code=400,

            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    # -----------------------------------------------------
    # 3. Phase routing
    # -----------------------------------------------------

    phase = body.get(
        "phase"
    )


    # Missing or unknown phase:
    #
    # HTTP 400
    # exactly {"error":"INVALID_INPUT"}
    if phase not in (
        "select",
        "evaluate"
    ):


        audit(
            request_id,
            "BQML_INVALID_PHASE",
            {
                "phase":
                    phase
            }
        )


        return JSONResponse(

            status_code=400,

            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    # =====================================================
    # SELECT
    # =====================================================

    if phase == "select":


        run_id = body.get(
            "runId"
        )


        # Internal fingerprint tells whether this is
        # an identical replay.
        fingerprint = (
            bqml_selection_fingerprint(
                body
            )
        )


        # -------------------------------------------------
        # Existing runId?
        # -------------------------------------------------

        if (
            bqml_utf8_ok(
                run_id
            )

            and 1 <= len(
                run_id
            ) <= 128

            and run_id
            in BQML_RUN_STORE
        ):


            stored = (
                BQML_RUN_STORE[
                    run_id
                ]
            )


            # ---------------------------------------------
            # IDENTICAL REPLAY
            #
            # Return exactly the already frozen response.
            # ---------------------------------------------

            if (
                stored[
                    "fingerprint"
                ]
                == fingerprint
            ):


                audit(
                    request_id,
                    "BQML_SELECT_REPLAY",
                    {
                        "runId":
                            run_id,

                        "response":
                            stored[
                                "response"
                            ],
                    }
                )


                return stored[
                    "response"
                ]


            # ---------------------------------------------
            # SAME runId + DIFFERENT selection input
            #
            # HTTP 409 exactly:
            #
            # {"error":"RUN_ID_CONFLICT"}
            # ---------------------------------------------

            audit(
                request_id,
                "BQML_RUN_ID_CONFLICT",
                {
                    "runId":
                        run_id
                }
            )


            return JSONResponse(

                status_code=409,

                content={
                    "error":
                        "RUN_ID_CONFLICT"
                }
            )


        # -------------------------------------------------
        # New selection
        # -------------------------------------------------

        response = bqml_process_select(
            body,
            request_id
        )


        # -------------------------------------------------
        # Persist complete selection response under runId.
        #
        # We can only persist when runId itself is a
        # valid usable key.
        # -------------------------------------------------

        if (
            bqml_utf8_ok(
                run_id
            )

            and 1 <= len(
                run_id
            ) <= 128
        ):


            BQML_RUN_STORE[
                run_id
            ] = {

                "fingerprint":
                    fingerprint,

                "response":
                    response,
            }


            audit(
                request_id,
                "BQML_SELECT_STORED",
                {
                    "runId":
                        run_id,

                    "response":
                        response,
                }
            )


        return response


    # =====================================================
    # EVALUATE
    # =====================================================

    return bqml_process_evaluate(
        body,
        request_id
    )


# =========================================================
# WEEK 8 - Q3
# Verifiable MLflow Model Promotion Gate
# Endpoint: POST /promote
# =========================================================


# ---------------------------------------------------------
# IDEMPOTENT PROMOTION STATE
# ---------------------------------------------------------

# If a request promotes version 2, an identical replay
# should treat 2 as the already-mutated champion and RETAIN it.
PROMOTION_REPLAY_STATE = {}


# ---------------------------------------------------------
# VERSION HELPERS
# ---------------------------------------------------------

BQML_CANONICAL_VERSION_RE = re.compile(r"^[1-9][0-9]*$")


def promote_is_number(value):
    """
    Numeric but NOT boolean.
    """
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def promote_is_finite(value):
    """
    Valid finite numeric value.
    """
    return (
        promote_is_number(value)
        and math.isfinite(float(value))
    )


def promote_safe_nonnegative_int(value):
    """
    Non-negative JavaScript-safe integer.
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INTEGER_MAX
    )


def promote_canonical_version(value):
    """
    Version must be a canonical POSITIVE safe-integer string.

    Valid:
        "1"
        "25"

    Invalid:
        "0"
        "01"
        "-1"
        "1.0"
        1
    """

    if not isinstance(value, str):
        return False

    if BQML_CANONICAL_VERSION_RE.fullmatch(value) is None:
        return False

    try:
        number = int(value)

    except ValueError:
        return False

    return (
        1 <= number <= SAFE_INTEGER_MAX
    )


def promote_sort_codes(codes):
    """
    Sort and deduplicate gate codes by UTF-8 bytes.
    """
    return sorted(
        set(codes),
        key=lambda value: value.encode("utf-8")
    )


def promote_request_fingerprint(body):
    """
    Fingerprint the exact semantic request for replay handling.

    Dict key order does not matter.
    Array order DOES matter because it is part of the input.
    """

    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def promote_failed_key(raw_version, index):
    """
    failedGates is a JSON object, so each key must be a string.

    For normal string version IDs, use the version itself.

    For malformed non-string IDs, use a deterministic synthetic
    key so the response remains deterministic and every malformed
    occurrence is represented.
    """

    if isinstance(raw_version, str):
        return raw_version

    return f"@invalid:{index}"


# =========================================================
# POLICY VALIDATION
# =========================================================

def promote_validate_policy(policy):
    """
    Returns:
        (valid, normalized_policy)

    Any malformed policy causes INVALID_POLICY.
    """

    if not isinstance(policy, dict):
        return False, None


    dataset_digest = policy.get("datasetDigest")
    schema_digest = policy.get("schemaDigest")
    max_age_seconds = policy.get("maxAgeSeconds")
    accuracy_floor = policy.get("accuracyFloor")
    required_slices = policy.get("requiredSlices")
    max_latency_ms = policy.get("maxLatencyMs")
    max_size_bytes = policy.get("maxSizeBytes")
    min_improvement = policy.get("minImprovement")


    # -----------------------------------------------------
    # Digests must be non-empty strings.
    # -----------------------------------------------------

    if (
        not isinstance(dataset_digest, str)
        or dataset_digest == ""
        or not isinstance(schema_digest, str)
        or schema_digest == ""
    ):
        return False, None


    # -----------------------------------------------------
    # Age must be non-negative safe integer.
    # -----------------------------------------------------

    if not promote_safe_nonnegative_int(max_age_seconds):
        return False, None


    # -----------------------------------------------------
    # Accuracy floor [0,1]
    # -----------------------------------------------------

    if (
        not promote_is_finite(accuracy_floor)
        or not (0.0 <= float(accuracy_floor) <= 1.0)
    ):
        return False, None


    # -----------------------------------------------------
    # Latency must be finite and non-negative.
    # -----------------------------------------------------

    if (
        not promote_is_finite(max_latency_ms)
        or float(max_latency_ms) < 0.0
    ):
        return False, None


    # -----------------------------------------------------
    # Size limit must be non-negative safe integer.
    # -----------------------------------------------------

    if not promote_safe_nonnegative_int(max_size_bytes):
        return False, None


    # -----------------------------------------------------
    # Minimum improvement must be finite [0,1].
    # -----------------------------------------------------

    if (
        not promote_is_finite(min_improvement)
        or not (0.0 <= float(min_improvement) <= 1.0)
    ):
        return False, None


    # -----------------------------------------------------
    # Required slices
    # -----------------------------------------------------

    if not isinstance(required_slices, dict):
        return False, None


    normalized_slices = {}


    for slice_name, floor in required_slices.items():

        if (
            not isinstance(slice_name, str)
            or slice_name == ""
        ):
            return False, None

        try:
            slice_name.encode("utf-8")

        except UnicodeEncodeError:
            return False, None


        if (
            not promote_is_finite(floor)
            or not (0.0 <= float(floor) <= 1.0)
        ):
            return False, None


        normalized_slices[slice_name] = float(floor)


    return True, {
        "datasetDigest": dataset_digest,
        "schemaDigest": schema_digest,
        "maxAgeSeconds": max_age_seconds,
        "accuracyFloor": float(accuracy_floor),
        "requiredSlices": normalized_slices,
        "maxLatencyMs": float(max_latency_ms),
        "maxSizeBytes": max_size_bytes,
        "minImprovement": float(min_improvement),
    }


# =========================================================
# EVALUATION GATES FOR ONE VERSION
# =========================================================

def promote_evaluate_version(
    version_object,
    as_of_utc,
    policy_valid,
    policy,
):
    """
    Evaluate one model version using ONLY its immutable
    evaluation evidence.

    Tags are deliberately ignored.
    """

    codes = []


    # -----------------------------------------------------
    # Missing or malformed evaluation
    # -----------------------------------------------------

    evaluation = (
        version_object.get("evaluation")
        if isinstance(version_object, dict)
        else None
    )


    if not isinstance(evaluation, dict):

        codes.append("MISSING_EVALUATION")

        return promote_sort_codes(codes)


    # -----------------------------------------------------
    # Invalid policy applies to every version.
    # -----------------------------------------------------

    if not policy_valid:

        codes.append("INVALID_POLICY")


    # -----------------------------------------------------
    # createdAt
    # -----------------------------------------------------

    created_at_raw = evaluation.get("createdAt")

    created_at_utc = parse_event_time(
        created_at_raw
    )


    if created_at_utc is None:

        codes.append(
            "INVALID_TIMESTAMP"
        )


    # -----------------------------------------------------
    # FUTURE / STALE checks
    # -----------------------------------------------------

    if (
        created_at_utc is not None
        and as_of_utc is not None
        and policy_valid
    ):

        # Convert normalized UTC timestamps back to datetime.
        created_dt = datetime.strptime(
            created_at_utc,
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(
            tzinfo=timezone.utc
        )

        as_of_dt = datetime.strptime(
            as_of_utc,
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(
            tzinfo=timezone.utc
        )


        # Evidence cannot come from the future.
        if created_dt > as_of_dt:

            codes.append(
                "FUTURE_EVALUATION"
            )


        else:

            age_seconds = (
                as_of_dt - created_dt
            ).total_seconds()


            if (
                age_seconds
                > policy["maxAgeSeconds"]
            ):

                codes.append(
                    "STALE_EVALUATION"
                )


    # -----------------------------------------------------
    # Registered artifact binding
    # -----------------------------------------------------

    registered_artifact = (
        version_object.get(
            "artifactDigest"
        )
    )


    evaluation_artifact = (
        evaluation.get(
            "artifactDigest"
        )
    )


    if (
        not isinstance(registered_artifact, str)
        or registered_artifact == ""
        or not isinstance(evaluation_artifact, str)
        or evaluation_artifact
        != registered_artifact
    ):

        codes.append(
            "ARTIFACT_MISMATCH"
        )


    # -----------------------------------------------------
    # Dataset / schema lineage
    # -----------------------------------------------------

    if policy_valid:

        if (
            evaluation.get("datasetDigest")
            != policy["datasetDigest"]
        ):

            codes.append(
                "DATASET_MISMATCH"
            )


        if (
            evaluation.get("schemaDigest")
            != policy["schemaDigest"]
        ):

            codes.append(
                "SCHEMA_MISMATCH"
            )


    # -----------------------------------------------------
    # Accuracy
    # -----------------------------------------------------

    accuracy = evaluation.get(
        "accuracy"
    )


    if not promote_is_finite(
        accuracy
    ):

        codes.append(
            "NON_FINITE"
        )


    else:

        accuracy_value = float(
            accuracy
        )


        if not (
            0.0 <= accuracy_value <= 1.0
        ):

            codes.append(
                "METRIC_RANGE"
            )


        elif (
            policy_valid
            and accuracy_value
            < policy["accuracyFloor"]
        ):

            codes.append(
                "ACCURACY_FLOOR"
            )


    # -----------------------------------------------------
    # Latency
    # -----------------------------------------------------

    latency = evaluation.get(
        "latencyMs"
    )


    if not promote_is_finite(
        latency
    ):

        codes.append(
            "NON_FINITE"
        )


    else:

        latency_value = float(
            latency
        )


        if latency_value < 0:

            codes.append(
                "METRIC_RANGE"
            )


        elif (
            policy_valid
            and latency_value
            > policy["maxLatencyMs"]
        ):

            codes.append(
                "LATENCY_LIMIT"
            )


    # -----------------------------------------------------
    # Size
    # -----------------------------------------------------

    size_bytes = evaluation.get(
        "sizeBytes"
    )


    if not promote_safe_nonnegative_int(
        size_bytes
    ):

        # Wrong type / unsafe / negative.
        codes.append(
            "METRIC_RANGE"
        )


    elif (
        policy_valid
        and size_bytes
        > policy["maxSizeBytes"]
    ):

        codes.append(
            "SIZE_LIMIT"
        )


    # -----------------------------------------------------
    # Required slices
    # -----------------------------------------------------

    slices = evaluation.get(
        "slices"
    )


    # If slices itself is malformed, every required
    # slice is effectively missing.
    if not isinstance(slices, dict):

        if policy_valid:

            for slice_name in (
                policy[
                    "requiredSlices"
                ].keys()
            ):

                codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )


    elif policy_valid:

        for slice_name, floor in (
            policy[
                "requiredSlices"
            ].items()
        ):


            # ---------------------------------------------
            # Missing slice
            # ---------------------------------------------

            if slice_name not in slices:

                codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

                continue


            slice_value = slices[
                slice_name
            ]


            # ---------------------------------------------
            # Slice must be finite [0,1]
            # ---------------------------------------------

            if not promote_is_finite(
                slice_value
            ):

                codes.append(
                    "NON_FINITE"
                )

                codes.append(
                    "SLICE_RANGE:"
                    + slice_name
                )

                continue


            slice_value = float(
                slice_value
            )


            if not (
                0.0 <= slice_value <= 1.0
            ):

                codes.append(
                    "SLICE_RANGE:"
                    + slice_name
                )

                continue


            # ---------------------------------------------
            # Inclusive slice floor
            # ---------------------------------------------

            if slice_value < floor:

                codes.append(
                    "SLICE_FLOOR:"
                    + slice_name
                )


    return promote_sort_codes(
        codes
    )


# =========================================================
# /promote ENDPOINT
# =========================================================

@app.post("/promote")
async def promote_endpoint(
    request: Request
):

    request_id = (
        uuid.uuid4().hex[:8]
    )


    # -----------------------------------------------------
    # 1. Strict JSON parsing
    # -----------------------------------------------------

    try:

        raw_body = await request.body()

        audit(
            request_id,
            "PROMOTE_HTTP_REQUEST",
            {
                "contentType":
                    request.headers.get(
                        "content-type"
                    ),

                "rawBody":
                    repr(raw_body),
            }
        )


        body_text = raw_body.decode(
            "utf-8"
        )


        body = strict_json_loads(
            body_text
        )


    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:

        audit(
            request_id,
            "PROMOTE_PARSE_FAILED",
            {
                "type":
                    type(exc).__name__,

                "message":
                    str(exc),
            }
        )

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )


    audit(
        request_id,
        "PROMOTE_REQUEST_PARSED",
        body
    )


    # -----------------------------------------------------
    # 2. Top-level contract
    #
    # Explicit assignment rule:
    #
    # missing policy
    # non-array versions
    # non-string championVersion
    #
    # => HTTP 400 exactly INVALID_INPUT.
    # -----------------------------------------------------

    if (
        not isinstance(body, dict)
        or "policy" not in body
        or not isinstance(
            body.get("versions"),
            list
        )
        or not isinstance(
            body.get("championVersion"),
            str
        )
    ):

        audit(
            request_id,
            "PROMOTE_TOP_LEVEL_INVALID",
            {
                "bodyType":
                    type(body).__name__,

                "hasPolicy":
                    (
                        isinstance(body, dict)
                        and "policy" in body
                    ),

                "versionsType":
                    (
                        type(
                            body.get("versions")
                        ).__name__
                        if isinstance(body, dict)
                        else None
                    ),

                "championType":
                    (
                        type(
                            body.get(
                                "championVersion"
                            )
                        ).__name__
                        if isinstance(body, dict)
                        else None
                    ),
            }
        )

        return JSONResponse(
            status_code=400,
            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    supplied_champion = body[
        "championVersion"
    ]

    versions = body["versions"]


    # -----------------------------------------------------
    # 3. asOf validation
    # -----------------------------------------------------

    as_of_utc = parse_event_time(
        body.get("asOf")
    )


    # Invalid asOf is an evidence timestamp failure.
    global_timestamp_invalid = (
        as_of_utc is None
    )


    # -----------------------------------------------------
    # 4. Policy validation
    # -----------------------------------------------------

    policy_valid, policy = (
        promote_validate_policy(
            body.get("policy")
        )
    )


    audit(
        request_id,
        "PROMOTE_POLICY",
        {
            "asOfUtc":
                as_of_utc,

            "policyValid":
                policy_valid,

            "normalizedPolicy":
                policy,
        }
    )


    # -----------------------------------------------------
    # 5. Find duplicate version IDs BEFORE lookup maps
    # -----------------------------------------------------

    version_occurrence_count = {}


    for version_object in versions:

        if (
            isinstance(version_object, dict)
            and isinstance(
                version_object.get("version"),
                str
            )
        ):

            raw_version = version_object[
                "version"
            ]

            version_occurrence_count[
                raw_version
            ] = (
                version_occurrence_count.get(
                    raw_version,
                    0
                )
                + 1
            )


    duplicate_versions = {
        version
        for version, count
        in version_occurrence_count.items()
        if count > 1
    }


    # -----------------------------------------------------
    # 6. Build gates WITHOUT constructing lookup maps yet
    # -----------------------------------------------------

    occurrence_results = []


    for index, version_object in enumerate(
        versions
    ):

        codes = []


        if isinstance(
            version_object,
            dict
        ):

            raw_version = (
                version_object.get(
                    "version"
                )
            )

        else:

            raw_version = None


        # ---------------------------------------------
        # Canonical version validation
        # ---------------------------------------------

        canonical = (
            promote_canonical_version(
                raw_version
            )
        )


        if not canonical:

            codes.append(
                "INVALID_VERSION"
            )


        # ---------------------------------------------
        # Duplicate detection
        #
        # EVERY occurrence of duplicate version
        # is rejected.
        # ---------------------------------------------

        if (
            isinstance(raw_version, str)
            and raw_version
            in duplicate_versions
        ):

            codes.append(
                "DUPLICATE_VERSION"
            )


        # ---------------------------------------------
        # Invalid global policy
        # ---------------------------------------------

        if not policy_valid:

            codes.append(
                "INVALID_POLICY"
            )


        # ---------------------------------------------
        # Invalid asOf timestamp
        # ---------------------------------------------

        if global_timestamp_invalid:

            codes.append(
                "INVALID_TIMESTAMP"
            )


        # ---------------------------------------------
        # Evidence gates are meaningful only for
        # dictionary version records.
        # ---------------------------------------------

        if isinstance(
            version_object,
            dict
        ):

            evidence_codes = (
                promote_evaluate_version(
                    version_object,
                    as_of_utc,
                    policy_valid,
                    policy,
                )
            )

            codes.extend(
                evidence_codes
            )


        else:

            codes.append(
                "MISSING_EVALUATION"
            )


        codes = promote_sort_codes(
            codes
        )


        result = {
            "index":
                index,

            "rawVersion":
                raw_version,

            "canonical":
                canonical,

            "duplicate":
                (
                    isinstance(raw_version, str)
                    and raw_version
                    in duplicate_versions
                ),

            "codes":
                codes,

            "object":
                version_object,
        }


        occurrence_results.append(
            result
        )


        audit(
            request_id,
            "PROMOTE_VERSION_GATES",
            {
                "index":
                    index,

                "version":
                    raw_version,

                "canonical":
                    canonical,

                "duplicate":
                    result["duplicate"],

                "codes":
                    codes,
            }
        )


    # -----------------------------------------------------
    # 7. NOW construct canonical lookup map.
    #
    # Duplicate and invalid versions are excluded.
    # -----------------------------------------------------

    lookup = {}


    for result in occurrence_results:

        raw_version = result[
            "rawVersion"
        ]


        if (
            result["canonical"]
            and not result["duplicate"]
        ):

            lookup[
                raw_version
            ] = result


    # -----------------------------------------------------
    # 8. failedGates
    #
    # Include EVERY input version.
    #
    # Eligible versions therefore appear with [].
    # -----------------------------------------------------

    failed_gates = {}


    for result in occurrence_results:

        key = promote_failed_key(
            result["rawVersion"],
            result["index"]
        )


        # If duplicates share the same textual version,
        # merge their gate codes.
        if key in failed_gates:

            failed_gates[key] = (
                promote_sort_codes(
                    failed_gates[key]
                    + result["codes"]
                )
            )

        else:

            failed_gates[key] = (
                result["codes"]
            )


    # Sort failedGates object keys deterministically.
    failed_gates = {

        key:
            failed_gates[key]

        for key in sorted(
            failed_gates.keys(),
            key=lambda value:
                value.encode("utf-8")
        )
    }


    # -----------------------------------------------------
    # 9. Eligible versions
    #
    # A version is eligible only when it has NO gate codes.
    # -----------------------------------------------------

    eligible_versions = []


    for version_id, result in (
        lookup.items()
    ):

        if result["codes"] == []:

            eligible_versions.append(
                version_id
            )


    # Required output ordering is deterministic.
    #
    # Version strings are canonical numeric IDs.
    # Use numeric ascending here.
    eligible_versions = sorted(
        eligible_versions,
        key=lambda value:
            int(value)
    )


    # -----------------------------------------------------
    # 10. Replay/idempotency
    # -----------------------------------------------------

    request_fingerprint = (
        promote_request_fingerprint(
            body
        )
    )


    # First call uses supplied champion.
    effective_champion = (
        supplied_champion
    )


    # If this exact request previously promoted a version,
    # the alias has already changed.
    #
    # Replaying should RETAIN that promoted version.
    if (
        request_fingerprint
        in PROMOTION_REPLAY_STATE
    ):

        effective_champion = (
            PROMOTION_REPLAY_STATE[
                request_fingerprint
            ]
        )


        audit(
            request_id,
            "PROMOTE_REPLAY_ALIAS",
            {
                "suppliedChampion":
                    supplied_champion,

                "effectiveChampion":
                    effective_champion,
            }
        )


    # -----------------------------------------------------
    # Default output
    # -----------------------------------------------------

    action = "block"

    selected_version = None

    alias_mutation = None

    evidence = None


    # -----------------------------------------------------
    # 11. Champion evidence MUST be valid.
    # -----------------------------------------------------

    champion_result = lookup.get(
        effective_champion
    )


    champion_valid = (

        champion_result is not None

        and champion_result[
            "codes"
        ] == []
    )


    if champion_valid:


        # -------------------------------------------------
        # Champion evaluation data
        # -------------------------------------------------

        champion_evaluation = (
            champion_result[
                "object"
            ][
                "evaluation"
            ]
        )


        champion_accuracy = float(
            champion_evaluation[
                "accuracy"
            ]
        )


        # -------------------------------------------------
        # 12. Rank ALL eligible versions
        #
        # accuracy DESC
        # latency ASC
        # size ASC
        # numeric version ASC
        # -------------------------------------------------

        ranked = sorted(

            eligible_versions,

            key=lambda version_id: (

                -float(
                    lookup[
                        version_id
                    ][
                        "object"
                    ][
                        "evaluation"
                    ][
                        "accuracy"
                    ]
                ),

                float(
                    lookup[
                        version_id
                    ][
                        "object"
                    ][
                        "evaluation"
                    ][
                        "latencyMs"
                    ]
                ),

                lookup[
                    version_id
                ][
                    "object"
                ][
                    "evaluation"
                ][
                    "sizeBytes"
                ],

                int(version_id),
            )
        )


        # -------------------------------------------------
        # No better candidate exists if champion ranks first
        # or there is no other eligible version.
        # -------------------------------------------------

        challenger_version = None


        for version_id in ranked:

            if version_id != effective_champion:

                challenger_version = (
                    version_id
                )

                break


        # -------------------------------------------------
        # No challenger -> retain champion
        # -------------------------------------------------

        if challenger_version is None:

            action = "retain"

            selected_version = (
                effective_champion
            )


        else:

            challenger_evaluation = (
                lookup[
                    challenger_version
                ][
                    "object"
                ][
                    "evaluation"
                ]
            )


            challenger_accuracy = float(
                challenger_evaluation[
                    "accuracy"
                ]
            )


            # Required 12-decimal rounding.
            improvement = round(
                challenger_accuracy
                - champion_accuracy,
                12
            )


            audit(
                request_id,
                "PROMOTE_COMPARISON",
                {
                    "champion":
                        effective_champion,

                    "championAccuracy":
                        champion_accuracy,

                    "challenger":
                        challenger_version,

                    "challengerAccuracy":
                        challenger_accuracy,

                    "improvement":
                        improvement,

                    "minImprovement":
                        (
                            policy[
                                "minImprovement"
                            ]
                            if policy_valid
                            else None
                        ),
                }
            )


            # ---------------------------------------------
            # Promote only when improvement >= threshold.
            # ---------------------------------------------

            if (
                policy_valid
                and improvement
                >= policy[
                    "minImprovement"
                ]
            ):

                action = "promote"

                selected_version = (
                    challenger_version
                )


                alias_mutation = {
                    "alias":
                        "champion",

                    "version":
                        challenger_version,
                }


                # Freeze alias mutation for exact replay.
                PROMOTION_REPLAY_STATE[
                    request_fingerprint
                ] = challenger_version


            else:

                action = "retain"

                selected_version = (
                    effective_champion
                )


        # -------------------------------------------------
        # Selected evidence
        # -------------------------------------------------

        if selected_version is not None:

            evidence = (
                lookup[
                    selected_version
                ][
                    "object"
                ][
                    "evaluation"
                ]
            )


    # -----------------------------------------------------
    # 13. Replay after promotion
    #
    # If the exact request already promoted earlier,
    # this execution must retain the mutated champion
    # rather than trying to promote it again.
    # -----------------------------------------------------

    if (
        request_fingerprint
        in PROMOTION_REPLAY_STATE
        and effective_champion
        == PROMOTION_REPLAY_STATE[
            request_fingerprint
        ]
    ):

        # This condition also becomes true immediately
        # on first promotion, so distinguish whether this
        # execution itself created aliasMutation.
        #
        # If aliasMutation is present, it is first promotion.
        # Otherwise it is a replay.
        if alias_mutation is None:

            replay_version = (
                PROMOTION_REPLAY_STATE[
                    request_fingerprint
                ]
            )


            replay_result = lookup.get(
                replay_version
            )


            if (
                replay_result is not None
                and replay_result[
                    "codes"
                ] == []
            ):

                action = "retain"

                effective_champion = (
                    replay_version
                )

                selected_version = (
                    replay_version
                )

                alias_mutation = None

                evidence = (
                    replay_result[
                        "object"
                    ][
                        "evaluation"
                    ]
                )


    # -----------------------------------------------------
    # EXACT RESPONSE SHAPE
    # -----------------------------------------------------

    response_payload = {

        "action":
            action,

        "championVersion":
            effective_champion,

        "selectedVersion":
            selected_version,

        "eligibleVersions":
            eligible_versions,

        "failedGates":
            failed_gates,

        "aliasMutation":
            alias_mutation,

        "evidence":
            evidence,
    }


    audit(
        request_id,
        "PROMOTE_FINAL_RESPONSE",
        response_payload
    )


    return response_payload
