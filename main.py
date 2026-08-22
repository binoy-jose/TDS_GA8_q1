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
# Promote the Right MLflow Model from Verifiable Evidence
# Endpoint: POST /promote
# =========================================================


# ---------------------------------------------------------
# PROMOTION STATE
# ---------------------------------------------------------
#
# This remembers an alias mutation.
#
# Example:
# champion 1 -> promote 3
#
# If the same immutable evidence is replayed later,
# version 3 is treated as the current champion.
#
PROMOTION_ALIAS_STATE = {}


# Canonical positive integer strings:
#
# VALID:
# "1"
# "2"
# "100"
#
# INVALID:
# "0"
# "01"
# "-1"
# "1.0"
#
PROMOTE_VERSION_RE = re.compile(
    r"^[1-9][0-9]*$"
)


# =========================================================
# BASIC HELPERS
# =========================================================

def promote_is_number(value):
    """
    True for int / float.

    False for boolean because Python considers
    True and False integers.
    """

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def promote_is_finite_number(value):
    """
    True only for a finite numeric value.
    """

    return (
        promote_is_number(value)
        and math.isfinite(float(value))
    )


def promote_is_safe_nonnegative_int(value):
    """
    Non-negative JavaScript-safe integer.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INTEGER_MAX
    )


def promote_is_canonical_version(value):
    """
    Version must be:

    - a string
    - positive
    - canonical
    - JavaScript-safe integer

    Examples:

        "1"  -> valid
        "01" -> invalid
        "0"  -> invalid
         14  -> invalid
    """

    if not isinstance(value, str):
        return False

    if PROMOTE_VERSION_RE.fullmatch(value) is None:
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
    Sort and deduplicate reason/gate codes
    using UTF-8 bytes.
    """

    return sorted(
        set(codes),
        key=lambda value:
            value.encode("utf-8")
    )


def promote_failed_key(
    raw_version,
    index
):
    """
    failedGates is a JSON object, so its keys
    must be strings.

    Normal version:
        "5" -> "5"

    Invalid numeric version:
        14 -> "14"

    Null:
        None -> "null"
    """

    if isinstance(raw_version, str):
        return raw_version

    try:

        return json.dumps(
            raw_version,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":")
        )

    except Exception:

        return (
            "@invalid:"
            + str(index)
        )


# =========================================================
# STATE / REPLAY FINGERPRINT
# =========================================================

def promote_state_fingerprint(body):
    """
    Build a fingerprint from immutable evidence.

    IMPORTANT:
    championVersion is NOT included because the
    champion alias may change after promotion.

    Mutable tags are NOT included because the problem
    explicitly says tags/descriptions are not evidence.
    """

    versions_for_state = []


    for version_object in body.get(
        "versions",
        []
    ):

        if isinstance(
            version_object,
            dict
        ):

            clean_version = {

                "version":
                    version_object.get(
                        "version"
                    ),

                "artifactDigest":
                    version_object.get(
                        "artifactDigest"
                    ),

                "evaluation":
                    version_object.get(
                        "evaluation"
                    ),
            }

            versions_for_state.append(
                clean_version
            )

        else:

            versions_for_state.append(
                version_object
            )


    # Order of input versions should not affect
    # the registry identity.
    versions_for_state = sorted(

        versions_for_state,

        key=lambda value:
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":")
            ).encode("utf-8")
    )


    state_object = {

        "asOf":
            body.get("asOf"),

        "policy":
            body.get("policy"),

        "versions":
            versions_for_state,
    }


    canonical = json.dumps(
        state_object,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )


    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


# =========================================================
# POLICY VALIDATION
# =========================================================

def promote_validate_policy(policy):
    """
    Validate promotion policy.

    Returns:

        (True, normalized_policy)

    or

        (False, None)
    """


    # Policy itself must be an object.
    if not isinstance(
        policy,
        dict
    ):

        return False, None


    dataset_digest = policy.get(
        "datasetDigest"
    )

    schema_digest = policy.get(
        "schemaDigest"
    )

    max_age_seconds = policy.get(
        "maxAgeSeconds"
    )

    accuracy_floor = policy.get(
        "accuracyFloor"
    )

    required_slices = policy.get(
        "requiredSlices"
    )

    max_latency_ms = policy.get(
        "maxLatencyMs"
    )

    max_size_bytes = policy.get(
        "maxSizeBytes"
    )

    min_improvement = policy.get(
        "minImprovement"
    )


    # -----------------------------------------------------
    # Dataset/schema digests must be non-empty strings.
    # -----------------------------------------------------

    if (
        not isinstance(
            dataset_digest,
            str
        )
        or dataset_digest == ""
        or not isinstance(
            schema_digest,
            str
        )
        or schema_digest == ""
    ):

        return False, None


    # -----------------------------------------------------
    # maxAgeSeconds:
    # non-negative safe integer
    # -----------------------------------------------------

    if not promote_is_safe_nonnegative_int(
        max_age_seconds
    ):

        return False, None


    # -----------------------------------------------------
    # accuracyFloor:
    # finite [0,1]
    # -----------------------------------------------------

    if (
        not promote_is_finite_number(
            accuracy_floor
        )
        or not (
            0.0
            <= float(accuracy_floor)
            <= 1.0
        )
    ):

        return False, None


    # -----------------------------------------------------
    # maxLatencyMs:
    # finite and non-negative
    # -----------------------------------------------------

    if (
        not promote_is_finite_number(
            max_latency_ms
        )
        or float(max_latency_ms) < 0.0
    ):

        return False, None


    # -----------------------------------------------------
    # maxSizeBytes:
    # non-negative safe integer
    # -----------------------------------------------------

    if not promote_is_safe_nonnegative_int(
        max_size_bytes
    ):

        return False, None


    # -----------------------------------------------------
    # minImprovement:
    # finite [0,1]
    # -----------------------------------------------------

    if (
        not promote_is_finite_number(
            min_improvement
        )
        or not (
            0.0
            <= float(min_improvement)
            <= 1.0
        )
    ):

        return False, None


    # -----------------------------------------------------
    # requiredSlices
    # -----------------------------------------------------

    if not isinstance(
        required_slices,
        dict
    ):

        return False, None


    normalized_required_slices = {}


    for (
        slice_name,
        slice_floor
    ) in required_slices.items():


        # JSON object keys are strings, but also make
        # sure they can be encoded to UTF-8.
        if not isinstance(
            slice_name,
            str
        ):

            return False, None


        try:

            slice_name.encode(
                "utf-8"
            )

        except UnicodeEncodeError:

            return False, None


        # Slice floor must be finite [0,1].
        if (
            not promote_is_finite_number(
                slice_floor
            )
            or not (
                0.0
                <= float(slice_floor)
                <= 1.0
            )
        ):

            return False, None


        normalized_required_slices[
            slice_name
        ] = float(
            slice_floor
        )


    # -----------------------------------------------------
    # Normalized policy
    # -----------------------------------------------------

    normalized = {

        "datasetDigest":
            dataset_digest,

        "schemaDigest":
            schema_digest,

        "maxAgeSeconds":
            max_age_seconds,

        "accuracyFloor":
            float(
                accuracy_floor
            ),

        "requiredSlices":
            normalized_required_slices,

        "maxLatencyMs":
            float(
                max_latency_ms
            ),

        "maxSizeBytes":
            max_size_bytes,

        "minImprovement":
            float(
                min_improvement
            ),
    }


    return True, normalized


# =========================================================
# NORMALIZED UTC -> DATETIME
# =========================================================

def promote_utc_to_datetime(
    normalized_time
):
    """
    Convert our Q1 timestamp format:

    2026-08-10T00:00:00.000Z

    into an aware datetime.
    """

    return datetime.strptime(
        normalized_time,
        "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(
        tzinfo=timezone.utc
    )


# =========================================================
# VALIDATE ONE VERSION'S EVIDENCE
# =========================================================

def promote_evaluate_evidence(
    version_object,
    as_of_utc,
    policy_valid,
    policy
):
    """
    Validate immutable evaluation evidence.

    Tags and descriptions are intentionally ignored.
    """

    codes = []


    # -----------------------------------------------------
    # Invalid policy
    # -----------------------------------------------------

    if not policy_valid:

        codes.append(
            "INVALID_POLICY"
        )


    # -----------------------------------------------------
    # Invalid asOf timestamp
    # -----------------------------------------------------

    if as_of_utc is None:

        codes.append(
            "INVALID_TIMESTAMP"
        )


    # -----------------------------------------------------
    # Evaluation object
    # -----------------------------------------------------

    evaluation = (
        version_object.get(
            "evaluation"
        )
    )


    if not isinstance(
        evaluation,
        dict
    ):

        codes.append(
            "MISSING_EVALUATION"
        )

        return promote_sort_codes(
            codes
        )


    # =====================================================
    # TIMESTAMP EVIDENCE
    # =====================================================

    created_at_utc = (
        parse_event_time(
            evaluation.get(
                "createdAt"
            )
        )
    )


    if created_at_utc is None:

        codes.append(
            "INVALID_TIMESTAMP"
        )


    # Only compare age when both timestamps are valid
    # and policy is valid.
    if (
        created_at_utc is not None
        and as_of_utc is not None
        and policy_valid
    ):

        created_dt = (
            promote_utc_to_datetime(
                created_at_utc
            )
        )

        as_of_dt = (
            promote_utc_to_datetime(
                as_of_utc
            )
        )


        # ---------------------------------------------
        # Future evidence
        # ---------------------------------------------

        if created_dt > as_of_dt:

            codes.append(
                "FUTURE_EVALUATION"
            )


        # ---------------------------------------------
        # Stale evidence
        # ---------------------------------------------

        else:

            age_seconds = (
                as_of_dt
                - created_dt
            ).total_seconds()


            if (
                age_seconds
                > policy[
                    "maxAgeSeconds"
                ]
            ):

                codes.append(
                    "STALE_EVALUATION"
                )


    # =====================================================
    # IMMUTABLE DIGEST BINDING
    # =====================================================

    registered_artifact = (
        version_object.get(
            "artifactDigest"
        )
    )


    evidence_artifact = (
        evaluation.get(
            "artifactDigest"
        )
    )


    # Evaluation artifact must exactly bind to
    # the registered artifact.
    if (
        not isinstance(
            registered_artifact,
            str
        )
        or registered_artifact == ""
        or not isinstance(
            evidence_artifact,
            str
        )
        or evidence_artifact
        != registered_artifact
    ):

        codes.append(
            "ARTIFACT_MISMATCH"
        )


    # Dataset/schema comparison needs a valid policy.
    if policy_valid:


        if (
            evaluation.get(
                "datasetDigest"
            )
            != policy[
                "datasetDigest"
            ]
        ):

            codes.append(
                "DATASET_MISMATCH"
            )


        if (
            evaluation.get(
                "schemaDigest"
            )
            != policy[
                "schemaDigest"
            ]
        ):

            codes.append(
                "SCHEMA_MISMATCH"
            )


    # =====================================================
    # ACCURACY
    # =====================================================

    accuracy = evaluation.get(
        "accuracy"
    )


    # Wrong type.
    if not promote_is_number(
        accuracy
    ):

        codes.append(
            "METRIC_RANGE"
        )


    # NaN / infinity.
    elif not math.isfinite(
        float(accuracy)
    ):

        codes.append(
            "NON_FINITE"
        )


    else:

        accuracy_value = float(
            accuracy
        )


        # Accuracy must be [0,1].
        if not (
            0.0
            <= accuracy_value
            <= 1.0
        ):

            codes.append(
                "METRIC_RANGE"
            )


        # Aggregate accuracy policy floor.
        elif (
            policy_valid
            and accuracy_value
            < policy[
                "accuracyFloor"
            ]
        ):

            codes.append(
                "ACCURACY_FLOOR"
            )


    # =====================================================
    # LATENCY
    # =====================================================

    latency = evaluation.get(
        "latencyMs"
    )


    if not promote_is_number(
        latency
    ):

        codes.append(
            "METRIC_RANGE"
        )


    elif not math.isfinite(
        float(latency)
    ):

        codes.append(
            "NON_FINITE"
        )


    else:

        latency_value = float(
            latency
        )


        # Latency must be non-negative.
        if latency_value < 0:

            codes.append(
                "METRIC_RANGE"
            )


        elif (
            policy_valid
            and latency_value
            > policy[
                "maxLatencyMs"
            ]
        ):

            codes.append(
                "LATENCY_LIMIT"
            )


    # =====================================================
    # SIZE
    # =====================================================

    size_bytes = evaluation.get(
        "sizeBytes"
    )


    # A numeric infinity should specifically be NON_FINITE.
    if (
        promote_is_number(
            size_bytes
        )
        and not math.isfinite(
            float(size_bytes)
        )
    ):

        codes.append(
            "NON_FINITE"
        )


    # Otherwise size must be a non-negative safe integer.
    elif not promote_is_safe_nonnegative_int(
        size_bytes
    ):

        codes.append(
            "METRIC_RANGE"
        )


    elif (
        policy_valid
        and size_bytes
        > policy[
            "maxSizeBytes"
        ]
    ):

        codes.append(
            "SIZE_LIMIT"
        )


    # =====================================================
    # SLICE VALIDATION
    # =====================================================

    slices = evaluation.get(
        "slices"
    )


    if isinstance(
        slices,
        dict
    ):


        # -------------------------------------------------
        # First validate every supplied slice value.
        # -------------------------------------------------

        for (
            slice_name,
            slice_value
        ) in slices.items():


            # Non-numeric slice value.
            #
            # Example:
            # "rare": "invalid"
            if not promote_is_number(
                slice_value
            ):

                codes.append(
                    "SLICE_RANGE:"
                    + slice_name
                )

                continue


            # NaN / infinity.
            if not math.isfinite(
                float(slice_value)
            ):

                codes.append(
                    "NON_FINITE"
                )

                continue


            numeric_slice = float(
                slice_value
            )


            # Finite but outside [0,1].
            if not (
                0.0
                <= numeric_slice
                <= 1.0
            ):

                codes.append(
                    "SLICE_RANGE:"
                    + slice_name
                )


        # -------------------------------------------------
        # Now check REQUIRED slices.
        # -------------------------------------------------

        if policy_valid:

            for (
                required_name,
                required_floor
            ) in policy[
                "requiredSlices"
            ].items():


                # Missing required slice.
                if (
                    required_name
                    not in slices
                ):

                    codes.append(
                        "MISSING_SLICE:"
                        + required_name
                    )

                    continue


                required_value = (
                    slices[
                        required_name
                    ]
                )


                # Invalid values already receive their
                # range/non-finite code above.
                #
                # Do not also apply SLICE_FLOOR.
                if (
                    not promote_is_number(
                        required_value
                    )
                    or not math.isfinite(
                        float(required_value)
                    )
                ):

                    continue


                required_value = float(
                    required_value
                )


                if not (
                    0.0
                    <= required_value
                    <= 1.0
                ):

                    continue


                # Inclusive floor:
                #
                # equal value PASSES.
                if (
                    required_value
                    < required_floor
                ):

                    codes.append(
                        "SLICE_FLOOR:"
                        + required_name
                    )


    else:

        # slices is missing/not an object.
        #
        # Every required slice is missing.
        if policy_valid:

            for required_name in (
                policy[
                    "requiredSlices"
                ].keys()
            ):

                codes.append(
                    "MISSING_SLICE:"
                    + required_name
                )


    return promote_sort_codes(
        codes
    )


# =========================================================
# RANKING HELPER
# =========================================================

def promote_rank_key(
    version_id,
    lookup
):
    """
    Required ranking:

    1. accuracy DESC
    2. latency ASC
    3. size ASC
    4. numeric version ASC
    """

    evaluation = (
        lookup[
            version_id
        ][
            "object"
        ][
            "evaluation"
        ]
    )


    return (

        -float(
            evaluation[
                "accuracy"
            ]
        ),

        float(
            evaluation[
                "latencyMs"
            ]
        ),

        evaluation[
            "sizeBytes"
        ],

        int(
            version_id
        ),
    )


# =========================================================
# MAIN /promote ENDPOINT
# =========================================================

@app.post("/promote")
async def promote_endpoint(
    request: Request
):


    request_id = (
        uuid.uuid4().hex[:8]
    )


    # =====================================================
    # 1. STRICT REQUEST PARSING
    # =====================================================

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
                    repr(
                        raw_body
                    ),
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
                    type(
                        exc
                    ).__name__,

                "message":
                    str(
                        exc
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


    # =====================================================
    # AUDIT PARSED REQUEST
    # =====================================================

    audit(
        request_id,
        "PROMOTE_REQUEST_PARSED",
        body
    )


    # =====================================================
    # 2. REQUIRED TOP-LEVEL CONTRACT
    # =====================================================
    #
    # Explicit assignment requirement:
    #
    # - missing policy
    # - versions not array
    # - championVersion not string
    #
    # => HTTP 400 exactly:
    #
    # {"error":"INVALID_INPUT"}
    # =====================================================

    if (
        not isinstance(
            body,
            dict
        )
        or "policy"
        not in body
        or not isinstance(
            body.get(
                "versions"
            ),
            list
        )
        or not isinstance(
            body.get(
                "championVersion"
            ),
            str
        )
    ):


        audit(
            request_id,
            "PROMOTE_TOP_LEVEL_INVALID",
            {
                "bodyType":
                    type(
                        body
                    ).__name__,

                "hasPolicy":
                    (
                        isinstance(
                            body,
                            dict
                        )
                        and "policy"
                        in body
                    ),

                "versionsType":
                    (
                        type(
                            body.get(
                                "versions"
                            )
                        ).__name__
                        if isinstance(
                            body,
                            dict
                        )
                        else None
                    ),

                "championType":
                    (
                        type(
                            body.get(
                                "championVersion"
                            )
                        ).__name__
                        if isinstance(
                            body,
                            dict
                        )
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


    # =====================================================
    # INPUT VALUES
    # =====================================================

    supplied_champion = (
        body[
            "championVersion"
        ]
    )


    versions = (
        body[
            "versions"
        ]
    )


    # =====================================================
    # 3. VALIDATE asOf
    # =====================================================

    as_of_utc = (
        parse_event_time(
            body.get(
                "asOf"
            )
        )
    )


    # =====================================================
    # 4. VALIDATE POLICY
    # =====================================================

    (
        policy_valid,
        policy
    ) = promote_validate_policy(
        body.get(
            "policy"
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


    # =====================================================
    # 5. IDENTIFY DUPLICATE VERSION STRINGS
    # =====================================================
    #
    # This happens BEFORE constructing lookup maps.
    #
    # Example:
    #
    # "2"
    # "2"
    #
    # BOTH occurrences are rejected.
    # =====================================================

    version_counts = {}


    for version_object in versions:


        if isinstance(
            version_object,
            dict
        ):

            raw_version = (
                version_object.get(
                    "version"
                )
            )


            if isinstance(
                raw_version,
                str
            ):

                version_counts[
                    raw_version
                ] = (
                    version_counts.get(
                        raw_version,
                        0
                    )
                    + 1
                )


    duplicate_versions = {

        version_id

        for (
            version_id,
            count
        ) in version_counts.items()

        if count > 1
    }


    # =====================================================
    # 6. VALIDATE EACH INPUT VERSION
    # =====================================================

    occurrence_results = []


    for (
        index,
        version_object
    ) in enumerate(
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


        # -------------------------------------------------
        # Canonical version?
        # -------------------------------------------------

        canonical = (
            promote_is_canonical_version(
                raw_version
            )
        )


        if not canonical:

            codes.append(
                "INVALID_VERSION"
            )


        # -------------------------------------------------
        # Duplicate version?
        # -------------------------------------------------

        duplicate = (

            isinstance(
                raw_version,
                str
            )

            and raw_version
            in duplicate_versions
        )


        if duplicate:

            codes.append(
                "DUPLICATE_VERSION"
            )


        # -------------------------------------------------
        # CRITICAL FIX:
        #
        # Duplicate / noncanonical versions are rejected
        # BEFORE evidence validation.
        #
        # We DO NOT inspect their evaluation, metrics,
        # digests or slices.
        # -------------------------------------------------

        identity_rejected = (
            not canonical
            or duplicate
        )


        if not identity_rejected:


            evidence_codes = (
                promote_evaluate_evidence(
                    version_object,
                    as_of_utc,
                    policy_valid,
                    policy
                )
            )


            codes.extend(
                evidence_codes
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
                duplicate,

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
                    duplicate,

                "codes":
                    codes,
            }
        )


    # =====================================================
    # 7. BUILD LOOKUP ONLY AFTER IDENTITY VALIDATION
    # =====================================================

    lookup = {}


    for result in occurrence_results:


        if (
            result[
                "canonical"
            ]
            and not result[
                "duplicate"
            ]
        ):

            lookup[
                result[
                    "rawVersion"
                ]
            ] = result


    # =====================================================
    # 8. BUILD failedGates
    # =====================================================
    #
    # Include every supplied version.
    #
    # Eligible versions therefore have:
    #
    # "3": []
    # =====================================================

    failed_gates = {}


    for result in occurrence_results:


        failed_key = (
            promote_failed_key(
                result[
                    "rawVersion"
                ],
                result[
                    "index"
                ]
            )
        )


        # Duplicate textual versions naturally map
        # to one JSON object key.
        #
        # Merge and deduplicate their codes.
        if failed_key in failed_gates:

            failed_gates[
                failed_key
            ] = promote_sort_codes(

                failed_gates[
                    failed_key
                ]

                + result[
                    "codes"
                ]
            )


        else:

            failed_gates[
                failed_key
            ] = result[
                "codes"
            ]


    # Deterministic UTF-8 key order.
    failed_gates = {

        key:
            failed_gates[
                key
            ]

        for key in sorted(

            failed_gates.keys(),

            key=lambda value:
                value.encode(
                    "utf-8"
                )
        )
    }


    # =====================================================
    # 9. FIND ELIGIBLE VERSIONS
    # =====================================================

    eligible_versions = []


    for (
        version_id,
        result
    ) in lookup.items():


        if result[
            "codes"
        ] == []:

            eligible_versions.append(
                version_id
            )


    # =====================================================
    # 10. RANK ELIGIBLE VERSIONS
    # =====================================================
    #
    # IMPORTANT:
    #
    # eligibleVersions itself must use this ranking:
    #
    # accuracy descending
    # latency ascending
    # size ascending
    # version ascending
    # =====================================================

    eligible_versions = sorted(

        eligible_versions,

        key=lambda version_id:
            promote_rank_key(
                version_id,
                lookup
            )
    )


    audit(
        request_id,
        "PROMOTE_ELIGIBLE_RANKING",
        {
            "eligibleVersions":
                eligible_versions,

            "rankDetails":
                [
                    {
                        "version":
                            version_id,

                        "accuracy":
                            lookup[
                                version_id
                            ][
                                "object"
                            ][
                                "evaluation"
                            ][
                                "accuracy"
                            ],

                        "latencyMs":
                            lookup[
                                version_id
                            ][
                                "object"
                            ][
                                "evaluation"
                            ][
                                "latencyMs"
                            ],

                        "sizeBytes":
                            lookup[
                                version_id
                            ][
                                "object"
                            ][
                                "evaluation"
                            ][
                                "sizeBytes"
                            ],
                    }

                    for version_id
                    in eligible_versions
                ],
        }
    )


    # =====================================================
    # 11. DETERMINE CURRENT CHAMPION / REPLAY STATE
    # =====================================================

    state_fingerprint = (
        promote_state_fingerprint(
            body
        )
    )


    effective_champion = (
        supplied_champion
    )


    # If an earlier call with this same immutable
    # evidence already mutated the alias, use the
    # stored champion.
    if (
        state_fingerprint
        in PROMOTION_ALIAS_STATE
    ):

        effective_champion = (
            PROMOTION_ALIAS_STATE[
                state_fingerprint
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


    # =====================================================
    # 12. DEFAULT BLOCK RESPONSE VALUES
    # =====================================================

    action = "block"

    selected_version = None

    alias_mutation = None

    evidence = None


    # =====================================================
    # 13. CHAMPION EVIDENCE MUST BE VALID
    # =====================================================

    champion_result = (
        lookup.get(
            effective_champion
        )
    )


    champion_valid = (

        champion_result
        is not None

        and champion_result[
            "codes"
        ] == []
    )


    # Invalid champion evidence:
    #
    # action = block
    # selectedVersion = null
    #
    # We simply leave defaults unchanged.
    if champion_valid:


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


        # =================================================
        # 14. BEST ELIGIBLE VERSION
        # =================================================
        #
        # eligibleVersions is already ranked.
        # =================================================

        if len(
            eligible_versions
        ) == 0:

            # This normally cannot happen if champion is
            # valid, because champion itself is eligible.
            action = "retain"

            selected_version = (
                effective_champion
            )


        else:

            best_version = (
                eligible_versions[0]
            )


            # ---------------------------------------------
            # Champion already ranks first.
            # ---------------------------------------------

            if (
                best_version
                == effective_champion
            ):

                action = "retain"

                selected_version = (
                    effective_champion
                )


            # ---------------------------------------------
            # A challenger ranks above champion.
            # ---------------------------------------------

            else:

                challenger_version = (
                    best_version
                )


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


                # Required:
                # round challenger - champion
                # to 12 decimal places.
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


                # -----------------------------------------
                # Promote when inclusive threshold passes.
                # -----------------------------------------

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


                    # Persist alias mutation.
                    PROMOTION_ALIAS_STATE[
                        state_fingerprint
                    ] = challenger_version


                # -----------------------------------------
                # Improvement too small -> retain champion.
                # -----------------------------------------

                else:

                    action = "retain"

                    selected_version = (
                        effective_champion
                    )


        # =================================================
        # 15. SELECT COMPLETE EVALUATION EVIDENCE
        # =================================================

        if selected_version is not None:

            selected_result = (
                lookup.get(
                    selected_version
                )
            )


            if (
                selected_result
                is not None
            ):

                # IMPORTANT:
                #
                # Return the COMPLETE original evaluation
                # object exactly as evidence.
                evidence = (
                    selected_result[
                        "object"
                    ][
                        "evaluation"
                    ]
                )


    # =====================================================
    # 16. FINAL RESPONSE
    # =====================================================
    #
    # Exact fields required by assignment.
    # =====================================================

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


    # =====================================================
    # FINAL AUDIT
    # =====================================================

    audit(
        request_id,
        "PROMOTE_FINAL_RESPONSE",
        response_payload
    )


    return response_payload


# =========================================================
# WEEK 8 - Q4
# Choose the Minimal Adaptation and Repair a PEFT Run
# Endpoint: POST /adapt
# =========================================================


# ---------------------------------------------------------
# Published priority order
# ---------------------------------------------------------

ADAPT_PRIORITY = [
    "prompt_only",
    "retrieval",
    "lora",
    "qlora",
]


# ---------------------------------------------------------
# Lineage regexes
# ---------------------------------------------------------

ADAPT_BASE_REVISION_RE = re.compile(
    r"^[0-9a-f]{40}$"
)

ADAPT_DIGEST_RE = re.compile(
    r"^[0-9a-f]{64}$"
)


# ---------------------------------------------------------
# Exact adapter files
# ---------------------------------------------------------

ADAPT_REQUIRED_FILES = [
    "adapter_config.json",
    "adapter_model.safetensors",
]


# ---------------------------------------------------------
# Required checkpoint keys
# ---------------------------------------------------------

ADAPT_CHECKPOINT_KEYS = {
    "model",
    "optimizer",
    "scheduler",
    "step",
    "rng",
    "dataPosition",
}


# =========================================================
# GENERAL HELPERS
# =========================================================

def adapt_is_number(value):
    """
    int/float but NOT bool.
    """

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def adapt_is_finite_number(value):
    """
    Finite numeric value.
    """

    return (
        adapt_is_number(value)
        and math.isfinite(float(value))
    )


def adapt_is_nonnegative_finite(value):
    """
    Finite number >= 0.
    """

    return (
        adapt_is_finite_number(value)
        and float(value) >= 0.0
    )


def adapt_is_safe_nonnegative_int(value):
    """
    Non-negative JavaScript-safe integer.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INTEGER_MAX
    )


def adapt_is_safe_positive_int(value):
    """
    Positive JavaScript-safe integer.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= SAFE_INTEGER_MAX
    )


def adapt_is_utf8_string(value):
    """
    String that can be encoded as UTF-8.
    """

    if not isinstance(value, str):
        return False

    try:
        value.encode("utf-8")
        return True

    except UnicodeEncodeError:
        return False


def adapt_is_nonempty_utf8_string(value):
    """
    Non-empty UTF-8 string.
    """

    return (
        adapt_is_utf8_string(value)
        and value != ""
    )


def adapt_sort_codes(codes):
    """
    Sort + deduplicate codes using UTF-8 bytes.
    """

    return sorted(
        set(codes),
        key=lambda value:
            value.encode("utf-8")
    )


# =========================================================
# CHOOSE OPERATION
# =========================================================

def adapt_validate_choose_policy(policy):

    if not isinstance(policy, dict):
        return False, None


    min_quality = policy.get(
        "minQuality"
    )

    freshness_required = policy.get(
        "freshnessRequired"
    )

    max_latency = policy.get(
        "maxLatencyMs"
    )

    max_memory = policy.get(
        "maxMemoryMb"
    )

    max_labeled = policy.get(
        "maxLabeledExamples"
    )

    max_total_cost = policy.get(
        "maxTotalCost"
    )

    horizon = policy.get(
        "horizonRequests"
    )


    # minQuality must be finite [0,1].
    if (
        not adapt_is_finite_number(
            min_quality
        )
        or not (
            0.0 <= float(min_quality) <= 1.0
        )
    ):
        return False, None


    # Must really be Boolean.
    if not isinstance(
        freshness_required,
        bool
    ):
        return False, None


    if not adapt_is_nonnegative_finite(
        max_latency
    ):
        return False, None


    if not adapt_is_nonnegative_finite(
        max_memory
    ):
        return False, None


    if not adapt_is_safe_nonnegative_int(
        max_labeled
    ):
        return False, None


    if not adapt_is_nonnegative_finite(
        max_total_cost
    ):
        return False, None


    if not adapt_is_safe_nonnegative_int(
        horizon
    ):
        return False, None


    return True, {

        "minQuality":
            float(min_quality),

        "freshnessRequired":
            freshness_required,

        "maxLatencyMs":
            float(max_latency),

        "maxMemoryMb":
            float(max_memory),

        "maxLabeledExamples":
            max_labeled,

        "maxTotalCost":
            float(max_total_cost),

        "horizonRequests":
            horizon,
    }


def adapt_candidate_structure_valid(candidate):

    if not isinstance(candidate, dict):
        return False


    name = candidate.get("name")

    available = candidate.get("available")

    quality = candidate.get("quality")

    freshness = candidate.get("freshness")

    latency = candidate.get("latencyMs")

    memory = candidate.get("memoryMb")

    labeled = candidate.get(
        "labeledExamples"
    )

    one_time = candidate.get(
        "oneTimeCost"
    )

    recurring = candidate.get(
        "recurringCost"
    )


    if name not in ADAPT_PRIORITY:
        return False


    if not isinstance(
        available,
        bool
    ):
        return False


    if (
        not adapt_is_finite_number(
            quality
        )
        or not (
            0.0 <= float(quality) <= 1.0
        )
    ):
        return False


    if not isinstance(
        freshness,
        bool
    ):
        return False


    if not adapt_is_nonnegative_finite(
        latency
    ):
        return False


    if not adapt_is_nonnegative_finite(
        memory
    ):
        return False


    if not adapt_is_safe_nonnegative_int(
        labeled
    ):
        return False


    if not adapt_is_nonnegative_finite(
        one_time
    ):
        return False


    if not adapt_is_nonnegative_finite(
        recurring
    ):
        return False


    return True


def adapt_process_choose(
    body,
    request_id
):

    policy_valid, policy = (
        adapt_validate_choose_policy(
            body.get("policy")
        )
    )


    candidates = body.get(
        "candidates"
    )


    # Exact output dictionaries.
    total_costs = {
        name: None
        for name in ADAPT_PRIORITY
    }


    reason_codes = {
        name: []
        for name in ADAPT_PRIORITY
    }


    candidate_contract_valid = (
        isinstance(candidates, list)
    )


    candidate_map = {}


    if candidate_contract_valid:

        # Exactly four candidates.
        if len(candidates) != 4:

            candidate_contract_valid = False

        else:

            for candidate in candidates:

                if not isinstance(
                    candidate,
                    dict
                ):

                    candidate_contract_valid = False
                    continue


                name = candidate.get(
                    "name"
                )


                if name not in ADAPT_PRIORITY:

                    candidate_contract_valid = False
                    continue


                # Duplicate candidate name.
                if name in candidate_map:

                    candidate_contract_valid = False
                    continue


                candidate_map[
                    name
                ] = candidate


            # Must contain exactly all four.
            if set(
                candidate_map.keys()
            ) != set(
                ADAPT_PRIORITY
            ):

                candidate_contract_valid = False


    # Malformed policy or candidate contract.
    if (
        not policy_valid
        or not candidate_contract_valid
    ):

        for name in ADAPT_PRIORITY:

            reason_codes[
                name
            ].append(
                "INVALID_INPUT"
            )


    # Evaluate each intervention.
    for name in ADAPT_PRIORITY:

        candidate = candidate_map.get(
            name
        )


        if candidate is None:
            continue


        candidate_valid = (
            adapt_candidate_structure_valid(
                candidate
            )
        )


        if not candidate_valid:

            reason_codes[
                name
            ].append(
                "INVALID_INPUT"
            )

            continue


        # ---------------------------------------------
        # Total cost
        # ---------------------------------------------

        if policy_valid:

            total = (

                float(
                    candidate[
                        "oneTimeCost"
                    ]
                )

                +

                (
                    policy[
                        "horizonRequests"
                    ]

                    * float(
                        candidate[
                            "recurringCost"
                        ]
                    )
                )
            )


            if math.isfinite(total):

                total_costs[
                    name
                ] = round(
                    total,
                    12
                )

            else:

                reason_codes[
                    name
                ].append(
                    "INVALID_INPUT"
                )


        if not policy_valid:
            continue


        # ---------------------------------------------
        # Availability
        # ---------------------------------------------

        if candidate[
            "available"
        ] is False:

            reason_codes[
                name
            ].append(
                "UNAVAILABLE"
            )


        # ---------------------------------------------
        # Quality
        # ---------------------------------------------

        if (
            float(
                candidate[
                    "quality"
                ]
            )
            < policy[
                "minQuality"
            ]
        ):

            reason_codes[
                name
            ].append(
                "QUALITY_FLOOR"
            )


        # ---------------------------------------------
        # Freshness
        # ---------------------------------------------

        if (
            policy[
                "freshnessRequired"
            ]
            and candidate[
                "freshness"
            ] is False
        ):

            reason_codes[
                name
            ].append(
                "FRESHNESS_REQUIRED"
            )


        # ---------------------------------------------
        # Latency
        # ---------------------------------------------

        if (
            float(
                candidate[
                    "latencyMs"
                ]
            )
            > policy[
                "maxLatencyMs"
            ]
        ):

            reason_codes[
                name
            ].append(
                "LATENCY_LIMIT"
            )


        # ---------------------------------------------
        # Memory
        # ---------------------------------------------

        if (
            float(
                candidate[
                    "memoryMb"
                ]
            )
            > policy[
                "maxMemoryMb"
            ]
        ):

            reason_codes[
                name
            ].append(
                "MEMORY_LIMIT"
            )


        # ---------------------------------------------
        # Labeled data
        # ---------------------------------------------

        if (
            candidate[
                "labeledExamples"
            ]
            > policy[
                "maxLabeledExamples"
            ]
        ):

            reason_codes[
                name
            ].append(
                "DATA_LIMIT"
            )


        # ---------------------------------------------
        # Cost
        # ---------------------------------------------

        if (
            total_costs[
                name
            ] is not None

            and total_costs[
                name
            ]
            > policy[
                "maxTotalCost"
            ]
        ):

            reason_codes[
                name
            ].append(
                "COST_LIMIT"
            )


    # Sort codes.
    for name in ADAPT_PRIORITY:

        reason_codes[
            name
        ] = adapt_sort_codes(
            reason_codes[
                name
            ]
        )


    # Eligible remains in published priority order.
    eligible = []


    if (
        policy_valid
        and candidate_contract_valid
    ):

        for name in ADAPT_PRIORITY:

            if (
                reason_codes[
                    name
                ] == []
            ):

                eligible.append(
                    name
                )


    selected = (
        eligible[0]
        if eligible
        else None
    )


    response = {

        "selected":
            selected,

        "eligible":
            eligible,

        "totalCosts":
            total_costs,

        "reasonCodes":
            reason_codes,
    }


    audit(
        request_id,
        "ADAPT_CHOOSE_RESULT",
        {
            "policyValid":
                policy_valid,

            "candidateContractValid":
                candidate_contract_valid,

            "response":
                response,
        }
    )


    return response


# =========================================================
# REPAIR HELPERS
# =========================================================

def adapt_validate_string_id_list(value):
    """
    Require:
    - non-empty list
    - non-empty UTF-8 strings
    - unique strings
    """

    if (
        not isinstance(value, list)
        or len(value) == 0
    ):

        return False


    seen = set()


    for item in value:

        if not adapt_is_nonempty_utf8_string(
            item
        ):

            return False


        if item in seen:

            return False


        seen.add(item)


    return True


def adapt_is_full_model_file(filename):
    """
    Detect common full-model weight artifacts.

    adapter_model.safetensors is explicitly allowed.
    """

    if not isinstance(
        filename,
        str
    ):
        return False


    base = filename.replace(
        "\\",
        "/"
    ).split("/")[-1]


    # Exact allowed adapter model is NOT full model.
    if base == "adapter_model.safetensors":
        return False


    # Common complete-model files.
    if base in {
        "pytorch_model.bin",
        "model.safetensors",
        "tf_model.h5",
        "flax_model.msgpack",
    }:

        return True


    # Sharded pytorch weights.
    if (
        base.startswith(
            "pytorch_model-"
        )
        and base.endswith(
            ".bin"
        )
    ):

        return True


    # Sharded full safetensors.
    if (
        base.startswith(
            "model-"
        )
        and base.endswith(
            ".safetensors"
        )
    ):

        return True


    return False


def adapt_validate_resume_array(value):

    if (
        not isinstance(value, list)
        or len(value) == 0
    ):

        return False


    return all(
        adapt_is_finite_number(
            item
        )
        for item in value
    )


# =========================================================
# REPAIR OPERATION
# =========================================================

def adapt_process_repair(
    body,
    request_id
):

    reason_codes = []


    # =====================================================
    # 1. TOKENS / LOSS LABELS
    # =====================================================

    tokens = body.get(
        "tokens"
    )


    tokens_valid = (
        isinstance(tokens, list)
        and len(tokens) > 0
    )


    if tokens_valid:

        for token in tokens:

            if not isinstance(
                token,
                dict
            ):

                tokens_valid = False
                break


            if not adapt_is_safe_nonnegative_int(
                token.get("id")
            ):

                tokens_valid = False
                break


            if token.get(
                "role"
            ) not in (
                "system",
                "user",
                "assistant",
            ):

                tokens_valid = False
                break


            if not isinstance(
                token.get("padding"),
                bool
            ):

                tokens_valid = False
                break


            if not isinstance(
                token.get("text"),
                str
            ):

                tokens_valid = False
                break


    labels = []


    if isinstance(tokens, list):

        # Any invalid token => ALL labels = -100.
        if not tokens_valid:

            labels = [
                -100
                for _ in tokens
            ]


        else:

            for token in tokens:

                if (
                    token[
                        "role"
                    ] == "assistant"

                    and token[
                        "padding"
                    ] is False
                ):

                    labels.append(
                        token[
                            "id"
                        ]
                    )

                else:

                    labels.append(
                        -100
                    )


    if not tokens_valid:

        reason_codes.append(
            "INVALID_TOKEN"
        )


    # =====================================================
    # 2. CHAT TEMPLATE
    # =====================================================

    template_applications = (
        body.get(
            "templateApplications"
        )
    )


    template_pass = (

        isinstance(
            template_applications,
            int
        )

        and not isinstance(
            template_applications,
            bool
        )

        and template_applications == 1
    )


    if not template_pass:

        reason_codes.append(
            "CHAT_TEMPLATE_COUNT"
        )


    # =====================================================
    # 3. ALLOWED LoRA TARGETS
    # =====================================================

    allowed_targets = body.get(
        "allowedTargets"
    )


    # -----------------------------------------------------
    # Build usable target values independently.
    #
    # Even if the array contains duplicates, we can still
    # identify which target strings were supplied.
    # The CONFIG will fail, but trainable parameters can
    # still be deterministically reported.
    # -----------------------------------------------------

    usable_allowed_targets = set()


    if isinstance(
        allowed_targets,
        list
    ):

        for target in allowed_targets:

            if adapt_is_nonempty_utf8_string(
                target
            ):

                usable_allowed_targets.add(
                    target
                )


    # -----------------------------------------------------
    # Strict contract for allowedTargets:
    #
    # - list
    # - non-empty
    # - every entry non-empty string
    # - unique
    # -----------------------------------------------------

    allowed_targets_valid = (

        isinstance(
            allowed_targets,
            list
        )

        and len(
            allowed_targets
        ) > 0

        and all(
            adapt_is_nonempty_utf8_string(
                target
            )
            for target
            in allowed_targets
        )

        and len(
            set(
                allowed_targets
            )
        )
        == len(
            allowed_targets
        )
    )


    # =====================================================
    # 4. PARAMETERS
    # =====================================================

    parameters = body.get(
        "parameters"
    )


    parameters_container_valid = (
        isinstance(
            parameters,
            list
        )
    )


    parameter_contract_valid = (
        parameters_container_valid
    )


    # -----------------------------------------------------
    # First pass:
    # find duplicate valid string parameter names.
    # -----------------------------------------------------

    parameter_name_counts = {}


    if parameters_container_valid:

        for parameter in parameters:

            if not isinstance(
                parameter,
                dict
            ):
                continue


            name = parameter.get(
                "name"
            )


            if adapt_is_nonempty_utf8_string(
                name
            ):

                parameter_name_counts[
                    name
                ] = (
                    parameter_name_counts.get(
                        name,
                        0
                    )
                    + 1
                )


    duplicate_parameter_names = {

        name

        for (
            name,
            count
        ) in parameter_name_counts.items()

        if count > 1
    }


    # -----------------------------------------------------
    # Second pass:
    # validate each parameter independently.
    #
    # IMPORTANT FIX:
    #
    # One malformed parameter does NOT erase all otherwise
    # valid LoRA parameters from trainableParams.
    # -----------------------------------------------------

    individually_valid_parameters = []


    if parameters_container_valid:

        for parameter in parameters:

            parameter_ok = isinstance(
                parameter,
                dict
            )


            if not parameter_ok:

                parameter_contract_valid = False
                continue


            name = parameter.get(
                "name"
            )

            target = parameter.get(
                "target"
            )

            numel = parameter.get(
                "numel"
            )


            # Name must be non-empty string.
            if not adapt_is_nonempty_utf8_string(
                name
            ):

                parameter_ok = False


            # Duplicate names invalidate EVERY occurrence.
            elif name in duplicate_parameter_names:

                parameter_ok = False


            # Target must be a non-empty string.
            if not adapt_is_nonempty_utf8_string(
                target
            ):

                parameter_ok = False


            # numel must be POSITIVE safe integer.
            if not adapt_is_safe_positive_int(
                numel
            ):

                parameter_ok = False


            if parameter_ok:

                individually_valid_parameters.append(
                    {
                        "name":
                            name,

                        "target":
                            target,

                        "numel":
                            numel,
                    }
                )

            else:

                parameter_contract_valid = False


    # Empty / non-list parameter input cannot satisfy PEFT.
    if (
        not parameters_container_valid
        or len(parameters) == 0
    ):

        parameter_contract_valid = False


    # -----------------------------------------------------
    # Select ONLY valid LoRA matrices whose target was
    # supplied in allowedTargets.
    #
    # We use usable_allowed_targets here even when the
    # allowedTargets array itself has a duplicate.
    #
    # That lets diagnostics still report deterministic
    # trainableParams while peftConfigPass remains false.
    # -----------------------------------------------------

    trainable_records = []


    for parameter in (
        individually_valid_parameters
    ):

        name = parameter[
            "name"
        ]

        target = parameter[
            "target"
        ]


        lora_suffix = (

            name.endswith(
                ".lora_A.weight"
            )

            or name.endswith(
                ".lora_B.weight"
            )
        )


        if (
            lora_suffix
            and target
            in usable_allowed_targets
        ):

            trainable_records.append(
                parameter
            )


    # Required UTF-8 ordering.
    trainable_records = sorted(

        trainable_records,

        key=lambda item:
            item[
                "name"
            ].encode(
                "utf-8"
            )
    )


    trainable_params = [

        item[
            "name"
        ]

        for item
        in trainable_records
    ]


    has_trainable_lora = (
        len(
            trainable_records
        ) > 0
    )


    # -----------------------------------------------------
    # Safely sum numel.
    # -----------------------------------------------------

    trainable_count = 0

    trainable_sum_safe = True


    for item in trainable_records:

        next_total = (
            trainable_count
            + item[
                "numel"
            ]
        )


        if next_total > SAFE_INTEGER_MAX:

            trainable_sum_safe = False
            break


        trainable_count = (
            next_total
        )


    # Never return an unsafe integer.
    if not trainable_sum_safe:

        trainable_count = 0


    # =====================================================
    # 5. INFERENCE MODE
    # =====================================================

    inference_mode_pass = (
        body.get(
            "inferenceMode"
        ) is False
    )


    if not inference_mode_pass:

        reason_codes.append(
            "INFERENCE_MODE"
        )


    # =====================================================
    # 6. PEFT CONFIG PASS
    # =====================================================

    peft_config_pass = (

        parameter_contract_valid

        and allowed_targets_valid

        and has_trainable_lora

        and trainable_sum_safe

        and inference_mode_pass
    )


    # Any PEFT parameter/target/count problem.
    if not (
        parameter_contract_valid

        and allowed_targets_valid

        and has_trainable_lora

        and trainable_sum_safe
    ):

        reason_codes.append(
            "INVALID_PARAMETER"
        )


    # =====================================================
    # 7. TRAIN / EVAL ISOLATION
    # =====================================================

    train_row_ids = body.get(
        "trainRowIds"
    )

    eval_row_ids = body.get(
        "evalRowIds"
    )


    train_ids_valid = (
        adapt_validate_string_id_list(
            train_row_ids
        )
    )

    eval_ids_valid = (
        adapt_validate_string_id_list(
            eval_row_ids
        )
    )


    eval_isolated = False


    if (
        train_ids_valid
        and eval_ids_valid
    ):

        eval_isolated = (
            set(
                train_row_ids
            ).isdisjoint(
                set(
                    eval_row_ids
                )
            )
        )


    if not eval_isolated:

        reason_codes.append(
            "EVAL_LEAKAGE"
        )


    # =====================================================
    # 8. EVALUATION DROPOUT
    # =====================================================

    evaluation_deterministic = (
        body.get(
            "dropoutActiveDuringEval"
        ) is False
    )


    if not evaluation_deterministic:

        reason_codes.append(
            "EVAL_DROPOUT_ACTIVE"
        )


    # =====================================================
    # 9. ARTIFACT FILES
    # =====================================================

    artifact_files = body.get(
        "artifactFiles"
    )


    artifact_list_valid = (

        isinstance(
            artifact_files,
            list
        )

        and all(
            adapt_is_nonempty_utf8_string(
                filename
            )
            for filename
            in artifact_files
        )
    )


    # -----------------------------------------------------
    # IMPORTANT FIX:
    #
    # Return the supplied artifact list in deterministic
    # UTF-8 order.
    #
    # Do NOT silently filter bad/extra/duplicate files out
    # of the response.
    # -----------------------------------------------------

    if artifact_list_valid:

        adapter_files = sorted(
            artifact_files,
            key=lambda value:
                value.encode(
                    "utf-8"
                )
        )

    else:

        adapter_files = []


    required_sorted = sorted(
        ADAPT_REQUIRED_FILES,
        key=lambda value:
            value.encode(
                "utf-8"
            )
    )


    # -----------------------------------------------------
    # Exact adapter file contract:
    #
    # adapter_config.json
    # adapter_model.safetensors
    #
    # exactly once each and NOTHING else.
    # -----------------------------------------------------

    adapter_file_set_pass = (

        artifact_list_valid

        and len(
            artifact_files
        ) == 2

        and adapter_files
        == required_sorted
    )


    if not adapter_file_set_pass:

        reason_codes.append(
            "ADAPTER_FILE_SET"
        )


    # -----------------------------------------------------
    # Full model artifact detection
    # -----------------------------------------------------

    full_model_artifact = False


    if artifact_list_valid:

        full_model_artifact = any(

            adapt_is_full_model_file(
                filename
            )

            for filename
            in artifact_files
        )


    if full_model_artifact:

        reason_codes.append(
            "FULL_MODEL_ARTIFACT"
        )


    # =====================================================
    # 10. CHECKPOINT
    # =====================================================

    checkpoint = body.get(
        "checkpoint"
    )


    checkpoint_complete = (

        isinstance(
            checkpoint,
            dict
        )

        and ADAPT_CHECKPOINT_KEYS.issubset(
            set(
                checkpoint.keys()
            )
        )
    )


    if not checkpoint_complete:

        reason_codes.append(
            "INCOMPLETE_CHECKPOINT"
        )


    # =====================================================
    # 11. BASE REVISION
    # =====================================================

    base_revision = body.get(
        "baseRevision"
    )


    base_revision_pass = (

        isinstance(
            base_revision,
            str
        )

        and ADAPT_BASE_REVISION_RE.fullmatch(
            base_revision
        )
        is not None
    )


    if not base_revision_pass:

        reason_codes.append(
            "MUTABLE_BASE_REVISION"
        )


    # =====================================================
    # 12. DATASET / CODE / CONFIG DIGEST LINEAGE
    # =====================================================

    dataset_digest = body.get(
        "datasetDigest"
    )

    code_digest = body.get(
        "codeDigest"
    )

    config_digest = body.get(
        "configDigest"
    )

    expected_digests = body.get(
        "expectedDigests"
    )


    dataset_digest_valid = (

        isinstance(
            dataset_digest,
            str
        )

        and ADAPT_DIGEST_RE.fullmatch(
            dataset_digest
        )
        is not None
    )


    code_digest_valid = (

        isinstance(
            code_digest,
            str
        )

        and ADAPT_DIGEST_RE.fullmatch(
            code_digest
        )
        is not None
    )


    config_digest_valid = (

        isinstance(
            config_digest,
            str
        )

        and ADAPT_DIGEST_RE.fullmatch(
            config_digest
        )
        is not None
    )


    expected_valid = isinstance(
        expected_digests,
        dict
    )


    lineage_digests_pass = False


    if (
        expected_valid
        and dataset_digest_valid
        and code_digest_valid
        and config_digest_valid
    ):

        lineage_digests_pass = (

            expected_digests.get(
                "datasetDigest"
            )
            == dataset_digest

            and expected_digests.get(
                "codeDigest"
            )
            == code_digest

            and expected_digests.get(
                "configDigest"
            )
            == config_digest
        )


    if not lineage_digests_pass:

        reason_codes.append(
            "LINEAGE_MISMATCH"
        )


    lineage_pass = (

        base_revision_pass
        and lineage_digests_pass
    )


    # =====================================================
    # 13. EFFECTIVE BATCH
    # =====================================================

    micro_batch = body.get(
        "microBatch"
    )

    gradient_accumulation = body.get(
        "gradientAccumulation"
    )

    replicas = body.get(
        "replicas"
    )

    expected_effective_batch = (
        body.get(
            "expectedEffectiveBatch"
        )
    )


    batch_fields_valid = all(

        adapt_is_safe_positive_int(
            value
        )

        for value in [
            micro_batch,
            gradient_accumulation,
            replicas,
            expected_effective_batch,
        ]
    )


    effective_batch_pass = False


    if batch_fields_valid:

        calculated_batch = (

            micro_batch

            * gradient_accumulation

            * replicas
        )


        effective_batch_pass = (

            calculated_batch
            <= SAFE_INTEGER_MAX

            and calculated_batch
            == expected_effective_batch
        )


    if not effective_batch_pass:

        reason_codes.append(
            "EFFECTIVE_BATCH_MISMATCH"
        )


    # =====================================================
    # 14. RESUME EQUIVALENCE
    # =====================================================

    uninterrupted_weights = (
        body.get(
            "uninterruptedWeights"
        )
    )

    resumed_weights = (
        body.get(
            "resumedWeights"
        )
    )

    resume_tolerance = body.get(
        "resumeTolerance"
    )


    uninterrupted_valid = (
        adapt_validate_resume_array(
            uninterrupted_weights
        )
    )

    resumed_valid = (
        adapt_validate_resume_array(
            resumed_weights
        )
    )

    tolerance_valid = (
        adapt_is_nonnegative_finite(
            resume_tolerance
        )
    )


    resume_pass = False


    if (
        uninterrupted_valid
        and resumed_valid
        and tolerance_valid
        and len(
            uninterrupted_weights
        )
        == len(
            resumed_weights
        )
    ):

        tolerance = float(
            resume_tolerance
        )


        resume_pass = all(

            abs(
                float(left)
                - float(right)
            )
            <= tolerance

            for (
                left,
                right
            ) in zip(
                uninterrupted_weights,
                resumed_weights
            )
        )


    if not resume_pass:

        reason_codes.append(
            "RESUME_DIVERGENCE"
        )


    # =====================================================
    # 15. SORT REASON CODES
    # =====================================================

    reason_codes = adapt_sort_codes(
        reason_codes
    )


    # =====================================================
    # 16. EXACT RESPONSE
    # =====================================================

    response = {

        "labels":
            labels,

        "templatePass":
            template_pass,

        "trainableParams":
            trainable_params,

        "trainableCount":
            trainable_count,

        "peftConfigPass":
            peft_config_pass,

        "adapterFiles":
            adapter_files,

        "checkpointComplete":
            checkpoint_complete,

        "lineagePass":
            lineage_pass,

        "evalIsolated":
            eval_isolated,

        "evaluationDeterministic":
            evaluation_deterministic,

        "resumePass":
            resume_pass,

        "reasonCodes":
            reason_codes,
    }


    # =====================================================
    # AUDIT
    # =====================================================

    audit(
        request_id,
        "ADAPT_REPAIR_RESULT",
        {
            "tokensValid":
                tokens_valid,

            "allowedTargetsValid":
                allowed_targets_valid,

            "usableAllowedTargets":
                sorted(
                    usable_allowed_targets,
                    key=lambda value:
                        value.encode("utf-8")
                ),

            "parameterContractValid":
                parameter_contract_valid,

            "duplicateParameterNames":
                sorted(
                    duplicate_parameter_names,
                    key=lambda value:
                        value.encode("utf-8")
                ),

            "individuallyValidParameters":
                individually_valid_parameters,

            "hasTrainableLora":
                has_trainable_lora,

            "trainableSumSafe":
                trainable_sum_safe,

            "artifactFileSetPass":
                adapter_file_set_pass,

            "fullModelArtifact":
                full_model_artifact,

            "baseRevisionPass":
                base_revision_pass,

            "lineageDigestsPass":
                lineage_digests_pass,

            "effectiveBatchPass":
                effective_batch_pass,

            "response":
                response,
        }
    )


    return response


# =========================================================
# MAIN /adapt ENDPOINT
# =========================================================

@app.post("/adapt")
async def adapt_endpoint(
    request: Request
):

    request_id = (
        uuid.uuid4().hex[:8]
    )


    # -----------------------------------------------------
    # Strict JSON parsing
    # -----------------------------------------------------

    try:

        raw_body = await request.body()


        audit(
            request_id,
            "ADAPT_HTTP_REQUEST",
            {
                "contentType":
                    request.headers.get(
                        "content-type"
                    ),

                "rawBody":
                    repr(
                        raw_body
                    ),
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
            "ADAPT_PARSE_FAILED",
            {
                "type":
                    type(
                        exc
                    ).__name__,

                "message":
                    str(
                        exc
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


    # -----------------------------------------------------
    # Audit parsed input
    # -----------------------------------------------------

    audit(
        request_id,
        "ADAPT_REQUEST_PARSED",
        body
    )


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


    operation = body.get(
        "operation"
    )


    # Missing/unknown operation.
    if operation not in (
        "choose",
        "repair",
    ):


        audit(
            request_id,
            "ADAPT_INVALID_OPERATION",
            {
                "operation":
                    operation
            }
        )


        return JSONResponse(
            status_code=400,
            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    if operation == "choose":

        return adapt_process_choose(
            body,
            request_id
        )


    return adapt_process_repair(
        body,
        request_id
    )


# =========================================================
# WEEK 8 - Q5
# Quantize and Admit a Model Under Explicit Constraints
# Endpoint: POST /quantize
# =========================================================


# ---------------------------------------------------------
# STATEFUL FREEZE STORE
# ---------------------------------------------------------
#
# Each valid freezeId stores:
#
# {
#     "fingerprint": "...",
#     "response": {...}
# }
#
QUANTIZE_FREEZE_STORE = {}


# =========================================================
# GENERAL HELPERS
# =========================================================

def quant_is_number(value):
    """
    int/float, but NOT Boolean.
    """

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def quant_is_finite_number(value):
    """
    Finite number.
    """

    return (
        quant_is_number(value)
        and math.isfinite(float(value))
    )


def quant_is_nonnegative_finite(value):
    """
    Finite number >= 0.
    """

    return (
        quant_is_finite_number(value)
        and float(value) >= 0.0
    )


def quant_is_safe_nonnegative_int(value):
    """
    Non-negative JavaScript-safe integer.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INTEGER_MAX
    )


def quant_is_utf8_string(value):
    """
    Valid UTF-8 string.
    """

    if not isinstance(value, str):
        return False

    try:
        value.encode("utf-8")
        return True

    except UnicodeEncodeError:
        return False


def quant_is_nonempty_utf8_string(value):
    """
    Non-empty UTF-8 string.
    """

    return (
        quant_is_utf8_string(value)
        and value != ""
    )


def quant_sort_codes(codes):
    """
    Sort + deduplicate reason codes
    using UTF-8 bytes.
    """

    return sorted(
        set(codes),
        key=lambda value:
            value.encode("utf-8")
    )


# =========================================================
# FREEZE REQUEST FINGERPRINT
# =========================================================

def quant_freeze_fingerprint(body):
    """
    Internal replay fingerprint.

    JSON object key order does not matter.
    Candidate array order is normalized by candidate name,
    because freeze output itself is sorted by name.
    """

    candidates = body.get(
        "candidates",
        []
    )


    normalized_candidates = []


    if isinstance(candidates, list):

        for candidate in candidates:

            normalized_candidates.append(
                candidate
            )


        normalized_candidates = sorted(
            normalized_candidates,
            key=lambda value:
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":")
                ).encode("utf-8")
        )


    allowed_reasons = body.get(
        "allowedUnsupportedReasons"
    )


    if isinstance(
        allowed_reasons,
        list
    ):

        normalized_allowed = sorted(
            allowed_reasons,
            key=lambda value:
                (
                    value.encode("utf-8")
                    if isinstance(value, str)
                    else repr(value).encode("utf-8")
                )
        )

    else:

        normalized_allowed = (
            allowed_reasons
        )


    fingerprint_object = {

        "phase":
            "freeze",

        "freezeId":
            body.get("freezeId"),

        "calibrationDigest":
            body.get(
                "calibrationDigest"
            ),

        "tokenizerDigest":
            body.get(
                "tokenizerDigest"
            ),

        "allowedUnsupportedReasons":
            normalized_allowed,

        "candidates":
            normalized_candidates,
    }


    canonical = json.dumps(
        fingerprint_object,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )


    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


# =========================================================
# INVENTORY CONSTRUCTION
# =========================================================

def quant_build_inventory(files):
    """
    Build the exact frozen inventory.

    Returns:
        (valid, inventory, totalBytes, packageDigest)

    Exact inventory key order:
        name
        bytes
        sha256
    """

    # files must be a non-empty object.
    if (
        not isinstance(files, dict)
        or len(files) == 0
    ):

        return (
            False,
            [],
            None,
            None,
        )


    inventory = []


    for (
        filename,
        content
    ) in files.items():


        # Filename must be a non-empty UTF-8 string.
        if not quant_is_nonempty_utf8_string(
            filename
        ):

            return (
                False,
                [],
                None,
                None,
            )


        # File CONTENT must be a UTF-8 string.
        #
        # Empty content is allowed.
        if not quant_is_utf8_string(
            content
        ):

            return (
                False,
                [],
                None,
                None,
            )


        raw_bytes = content.encode(
            "utf-8"
        )


        inventory.append({

            # Keep this exact key order.
            "name":
                filename,

            "bytes":
                len(raw_bytes),

            "sha256":
                hashlib.sha256(
                    raw_bytes
                ).hexdigest(),
        })


    # Sort by UTF-8 filename.
    inventory = sorted(
        inventory,
        key=lambda item:
            item[
                "name"
            ].encode("utf-8")
    )


    # Safely sum bytes.
    total_bytes = 0


    for item in inventory:

        next_total = (
            total_bytes
            + item[
                "bytes"
            ]
        )


        if next_total > SAFE_INTEGER_MAX:

            return (
                False,
                [],
                None,
                None,
            )


        total_bytes = (
            next_total
        )


    # Exact compact JSON of inventory.
    inventory_json = json.dumps(
        inventory,
        ensure_ascii=False,
        separators=(",", ":")
    )


    package_digest = hashlib.sha256(
        inventory_json.encode(
            "utf-8"
        )
    ).hexdigest()


    return (
        True,
        inventory,
        total_bytes,
        package_digest,
    )


# =========================================================
# FREEZE OPERATION
# =========================================================

def quant_process_freeze(
    body,
    request_id
):

    freeze_id = body.get(
        "freezeId"
    )


    request_calibration = body.get(
        "calibrationDigest"
    )

    request_tokenizer = body.get(
        "tokenizerDigest"
    )

    allowed_reasons = body.get(
        "allowedUnsupportedReasons"
    )

    candidates = body.get(
        "candidates"
    )


    # -----------------------------------------------------
    # Global freeze fields
    # -----------------------------------------------------

    freeze_id_valid = (

        quant_is_nonempty_utf8_string(
            freeze_id
        )

        and len(
            freeze_id
        ) <= 128
    )


    calibration_valid = (
        quant_is_nonempty_utf8_string(
            request_calibration
        )
    )


    tokenizer_valid = (
        quant_is_nonempty_utf8_string(
            request_tokenizer
        )
    )


    allowed_reasons_valid = (

        isinstance(
            allowed_reasons,
            list
        )

        and all(
            quant_is_nonempty_utf8_string(
                reason
            )
            for reason
            in allowed_reasons
        )

        and len(
            set(
                allowed_reasons
            )
        )
        == len(
            allowed_reasons
        )
    )


    allowed_reason_set = (

        set(
            allowed_reasons
        )

        if allowed_reasons_valid

        else set()
    )


    global_valid = (

        freeze_id_valid

        and calibration_valid

        and tokenizer_valid

        and allowed_reasons_valid
    )


    # -----------------------------------------------------
    # Duplicate candidate names
    # -----------------------------------------------------

    candidate_name_counts = {}


    for candidate in candidates:

        if not isinstance(
            candidate,
            dict
        ):
            continue


        name = candidate.get(
            "name"
        )


        if quant_is_nonempty_utf8_string(
            name
        ):

            candidate_name_counts[
                name
            ] = (
                candidate_name_counts.get(
                    name,
                    0
                )
                + 1
            )


    duplicate_names = {

        name

        for (
            name,
            count
        ) in candidate_name_counts.items()

        if count > 1
    }


    output_candidates = []


    # =====================================================
    # Validate every candidate
    # =====================================================

    for (
        candidate_index,
        candidate
    ) in enumerate(
        candidates
    ):

        reason_codes = []


        if isinstance(
            candidate,
            dict
        ):

            name = candidate.get(
                "name"
            )

            files = candidate.get(
                "files"
            )

            loadable = candidate.get(
                "loadable"
            )

            calibration_digest = (
                candidate.get(
                    "calibrationDigest"
                )
            )

            tokenizer_digest = (
                candidate.get(
                    "tokenizerDigest"
                )
            )

            unsupported_reason = (
                candidate.get(
                    "unsupportedReason"
                )
            )


        else:

            name = None

            files = None

            loadable = None

            calibration_digest = None

            tokenizer_digest = None

            unsupported_reason = None


        # -------------------------------------------------
        # Name
        # -------------------------------------------------

        name_valid = (
            quant_is_nonempty_utf8_string(
                name
            )
        )


        if not name_valid:

            reason_codes.append(
                "INVALID_INPUT"
            )


        if (
            isinstance(name, str)
            and name in duplicate_names
        ):

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # Global malformed freeze fields invalidate
        # every candidate.
        # -------------------------------------------------

        if not global_valid:

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # Files / inventory
        # -------------------------------------------------

        (
            files_valid,
            inventory,
            total_bytes,
            package_digest,
        ) = quant_build_inventory(
            files
        )


        if not files_valid:

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # loadable must be Boolean.
        # -------------------------------------------------

        if not isinstance(
            loadable,
            bool
        ):

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # Candidate calibration/tokenizer digests
        # must themselves be strings.
        # -------------------------------------------------

        candidate_calibration_valid = (
            quant_is_nonempty_utf8_string(
                calibration_digest
            )
        )


        candidate_tokenizer_valid = (
            quant_is_nonempty_utf8_string(
                tokenizer_digest
            )
        )


        if not candidate_calibration_valid:

            reason_codes.append(
                "INVALID_INPUT"
            )


        if not candidate_tokenizer_valid:

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # unsupportedReason
        #
        # Accepted representations of "no reason":
        # - missing
        # - null
        # - ""
        #
        # Non-empty string means there is a reason.
        # -------------------------------------------------

        unsupported_present = False


        if unsupported_reason is None:

            unsupported_present = False


        elif unsupported_reason == "":

            unsupported_present = False


        elif quant_is_nonempty_utf8_string(
            unsupported_reason
        ):

            unsupported_present = True


        else:

            reason_codes.append(
                "INVALID_INPUT"
            )


        # -------------------------------------------------
        # Allowed unsupported case
        # -------------------------------------------------

        allowed_unsupported = (

            unsupported_present

            and allowed_reasons_valid

            and unsupported_reason
            in allowed_reason_set
        )


        # -------------------------------------------------
        # Unallowed unsupported reason
        # -------------------------------------------------

        if (
            unsupported_present
            and not allowed_unsupported
        ):

            reason_codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )


        # -------------------------------------------------
        # Normal loadability + lineage gates
        #
        # An ALLOWED unsupported candidate is classified
        # unsupported and does not need to pass these.
        # -------------------------------------------------

        if not allowed_unsupported:


            if (
                isinstance(
                    loadable,
                    bool
                )
                and loadable is False
            ):

                reason_codes.append(
                    "NOT_LOADABLE"
                )


            if (
                calibration_valid
                and candidate_calibration_valid
                and calibration_digest
                != request_calibration
            ):

                reason_codes.append(
                    "CALIBRATION_MISMATCH"
                )


            if (
                tokenizer_valid
                and candidate_tokenizer_valid
                and tokenizer_digest
                != request_tokenizer
            ):

                reason_codes.append(
                    "TOKENIZER_MISMATCH"
                )


        # -------------------------------------------------
        # Sort / dedupe codes
        # -------------------------------------------------

        reason_codes = quant_sort_codes(
            reason_codes
        )


        # -------------------------------------------------
        # Status
        #
        # ANY reason code => invalid.
        # -------------------------------------------------

        if reason_codes:

            status = "invalid"


        elif allowed_unsupported:

            status = "unsupported"


        else:

            status = "frozen"


        output_candidate = {

            "name":
                name,

            "status":
                status,

            "inventory":
                (
                    inventory
                    if files_valid
                    else []
                ),

            "totalBytes":
                (
                    total_bytes
                    if files_valid
                    else None
                ),

            "packageDigest":
                (
                    package_digest
                    if files_valid
                    else None
                ),

            "reasonCodes":
                reason_codes,
        }


        output_candidates.append(
            output_candidate
        )


        audit(
            request_id,
            "QUANTIZE_FREEZE_CANDIDATE",
            {
                "index":
                    candidate_index,

                "name":
                    name,

                "filesValid":
                    files_valid,

                "allowedUnsupported":
                    allowed_unsupported,

                "responseCandidate":
                    output_candidate,
            }
        )


    # -----------------------------------------------------
    # Sort candidates by UTF-8 name.
    #
    # Invalid/non-string names use deterministic fallback.
    # -----------------------------------------------------

    def candidate_sort_key(item):

        name = item.get(
            "name"
        )


        if isinstance(name, str):

            return (
                0,
                name.encode("utf-8")
            )


        return (
            1,
            compact_json(
                item
            ).encode("utf-8")
        )


    output_candidates = sorted(
        output_candidates,
        key=candidate_sort_key
    )


    response = {

        "freezeId":
            freeze_id,

        "candidates":
            output_candidates,
    }


    audit(
        request_id,
        "QUANTIZE_FREEZE_RESPONSE",
        response
    )


    return (
        response,
        freeze_id_valid
    )


# =========================================================
# RECOMPUTE / VERIFY FROZEN MANIFEST
# =========================================================

def quant_verify_manifest(candidate):
    """
    Recompute:

    - inventory validity
    - totalBytes
    - packageDigest

    NEVER trust submitted totalBytes/packageDigest.

    Returns:
        (
            manifest_valid,
            recomputed_total,
            recomputed_package_digest
        )
    """


    if not isinstance(
        candidate,
        dict
    ):

        return (
            False,
            None,
            None,
        )


    inventory = candidate.get(
        "inventory"
    )


    if not isinstance(
        inventory,
        list
    ):

        return (
            False,
            None,
            None,
        )


    normalized_inventory = []

    seen_names = set()

    total_bytes = 0


    for entry in inventory:


        if not isinstance(
            entry,
            dict
        ):

            return (
                False,
                None,
                None,
            )


        # Exact inventory keys.
        if set(
            entry.keys()
        ) != {
            "name",
            "bytes",
            "sha256",
        }:

            return (
                False,
                None,
                None,
            )


        filename = entry.get(
            "name"
        )

        file_bytes = entry.get(
            "bytes"
        )

        file_sha = entry.get(
            "sha256"
        )


        if not quant_is_nonempty_utf8_string(
            filename
        ):

            return (
                False,
                None,
                None,
            )


        if filename in seen_names:

            return (
                False,
                None,
                None,
            )


        seen_names.add(
            filename
        )


        if not quant_is_safe_nonnegative_int(
            file_bytes
        ):

            return (
                False,
                None,
                None,
            )


        if (
            not isinstance(
                file_sha,
                str
            )
            or re.fullmatch(
                r"[0-9a-f]{64}",
                file_sha
            )
            is None
        ):

            return (
                False,
                None,
                None,
            )


        # Inventory must already be represented with
        # exact key order when hashing.
        normalized_inventory.append({

            "name":
                filename,

            "bytes":
                file_bytes,

            "sha256":
                file_sha,
        })


    # Required filename ordering.
    normalized_inventory = sorted(
        normalized_inventory,
        key=lambda item:
            item[
                "name"
            ].encode("utf-8")
    )


    # Submitted inventory itself must already be
    # in this deterministic order.
    if inventory != normalized_inventory:

        return (
            False,
            None,
            None,
        )


    # Safe byte total.
    for entry in normalized_inventory:

        next_total = (
            total_bytes
            + entry[
                "bytes"
            ]
        )


        if next_total > SAFE_INTEGER_MAX:

            return (
                False,
                None,
                None,
            )


        total_bytes = (
            next_total
        )


    inventory_json = json.dumps(
        normalized_inventory,
        ensure_ascii=False,
        separators=(",", ":")
    )


    package_digest = hashlib.sha256(
        inventory_json.encode(
            "utf-8"
        )
    ).hexdigest()


    submitted_total = candidate.get(
        "totalBytes"
    )

    submitted_digest = candidate.get(
        "packageDigest"
    )


    manifest_valid = (

        submitted_total
        == total_bytes

        and submitted_digest
        == package_digest
    )


    return (
        manifest_valid,
        total_bytes,
        package_digest,
    )


# =========================================================
# SELECT POLICY VALIDATION
# =========================================================

def quant_validate_select_policy(policy):
    """
    Validate selection policy.

    Returns:
        (valid, normalized_policy)
    """

    if not isinstance(
        policy,
        dict
    ):

        return False, None


    max_bytes = policy.get(
        "maxBytes"
    )

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    required_slices = policy.get(
        "requiredSlices"
    )

    max_latency = policy.get(
        "maxLatencyMs"
    )

    candidate_order = policy.get(
        "candidateOrder"
    )


    # -----------------------------------------------------
    # maxBytes
    # -----------------------------------------------------

    if not quant_is_safe_nonnegative_int(
        max_bytes
    ):

        return False, None


    # -----------------------------------------------------
    # aggregateFloor
    # -----------------------------------------------------

    if (
        not quant_is_finite_number(
            aggregate_floor
        )
        or not (
            0.0
            <= float(
                aggregate_floor
            )
            <= 1.0
        )
    ):

        return False, None


    # -----------------------------------------------------
    # requiredSlices
    # -----------------------------------------------------

    if not isinstance(
        required_slices,
        dict
    ):

        return False, None


    normalized_slices = {}


    for (
        slice_name,
        slice_floor
    ) in required_slices.items():


        if not quant_is_nonempty_utf8_string(
            slice_name
        ):

            return False, None


        if (
            not quant_is_finite_number(
                slice_floor
            )
            or not (
                0.0
                <= float(
                    slice_floor
                )
                <= 1.0
            )
        ):

            return False, None


        normalized_slices[
            slice_name
        ] = float(
            slice_floor
        )


    # -----------------------------------------------------
    # maxLatencyMs
    # -----------------------------------------------------

    if not quant_is_nonnegative_finite(
        max_latency
    ):

        return False, None


    # -----------------------------------------------------
    # candidateOrder
    # -----------------------------------------------------

    if (
        not isinstance(
            candidate_order,
            list
        )
        or len(
            candidate_order
        ) == 0
        or not all(
            quant_is_nonempty_utf8_string(
                name
            )
            for name
            in candidate_order
        )
        or len(
            set(
                candidate_order
            )
        )
        != len(
            candidate_order
        )
    ):

        return False, None


    return True, {

        "maxBytes":
            max_bytes,

        "aggregateFloor":
            float(
                aggregate_floor
            ),

        "requiredSlices":
            normalized_slices,

        "maxLatencyMs":
            float(
                max_latency
            ),

        "candidateOrder":
            candidate_order,
    }


# =========================================================
# SELECT OPERATION
# =========================================================

def quant_process_select(
    body,
    request_id
):

    freeze_id = body.get(
        "freezeId"
    )

    submitted_candidates = body.get(
        "candidates"
    )

    rows = body.get(
        "rows"
    )

    policy_raw = body.get(
        "policy"
    )

    latencies = body.get(
        "latencies"
    )


    # -----------------------------------------------------
    # Stored freeze
    # -----------------------------------------------------

    stored = (
        QUANTIZE_FREEZE_STORE.get(
            freeze_id
        )
        if isinstance(
            freeze_id,
            str
        )
        else None
    )


    stored_candidates = (

        stored[
            "response"
        ][
            "candidates"
        ]

        if stored is not None

        else None
    )


    # -----------------------------------------------------
    # Exact lineage equality
    # -----------------------------------------------------

    lineage_valid = (

        stored_candidates
        is not None

        and submitted_candidates
        == stored_candidates
    )


    # -----------------------------------------------------
    # Policy
    # -----------------------------------------------------

    (
        policy_valid,
        policy
    ) = quant_validate_select_policy(
        policy_raw
    )


    # -----------------------------------------------------
    # Candidate name sets
    # -----------------------------------------------------

    candidate_names_valid = True

    submitted_names = []


    if isinstance(
        submitted_candidates,
        list
    ):

        for candidate in (
            submitted_candidates
        ):

            if (
                not isinstance(
                    candidate,
                    dict
                )
                or not quant_is_nonempty_utf8_string(
                    candidate.get(
                        "name"
                    )
                )
            ):

                candidate_names_valid = False
                continue


            submitted_names.append(
                candidate[
                    "name"
                ]
            )


        if len(
            submitted_names
        ) != len(
            set(
                submitted_names
            )
        ):

            candidate_names_valid = False


    else:

        candidate_names_valid = False


    # -----------------------------------------------------
    # candidateOrder must be same unique SET.
    # -----------------------------------------------------

    candidate_order_set_valid = False


    if (
        policy_valid
        and candidate_names_valid
    ):

        candidate_order_set_valid = (

            set(
                policy[
                    "candidateOrder"
                ]
            )
            == set(
                submitted_names
            )

            and len(
                policy[
                    "candidateOrder"
                ]
            )
            == len(
                submitted_names
            )
        )


    # -----------------------------------------------------
    # Latencies object
    # -----------------------------------------------------

    latency_container_valid = (
        isinstance(
            latencies,
            dict
        )
    )


    # =====================================================
    # ROW STRUCTURE
    # =====================================================

    global_row_structure_valid = (
        isinstance(
            rows,
            list
        )
    )


    # A prediction validity map by candidate.
    predictions_valid = {
        name: True
        for name in submitted_names
    }


    # Normalized test rows.
    normalized_rows = []


    if global_row_structure_valid:

        for row in rows:


            row_basic_valid = isinstance(
                row,
                dict
            )


            if row_basic_valid:

                label = row.get(
                    "label"
                )

                slice_name = row.get(
                    "slice"
                )

                predictions = row.get(
                    "predictions"
                )


                label_valid = (

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


                slice_valid = (
                    quant_is_nonempty_utf8_string(
                        slice_name
                    )
                )


                prediction_object_valid = (
                    isinstance(
                        predictions,
                        dict
                    )
                )


                row_basic_valid = (

                    label_valid

                    and slice_valid

                    and prediction_object_valid
                )


            # Invalid label/slice/predictions object means
            # predictions are unusable for ALL candidates.
            if not row_basic_valid:

                for name in submitted_names:

                    predictions_valid[
                        name
                    ] = False

                continue


            # Validate each candidate's prediction.
            normalized_predictions = {}


            for name in submitted_names:

                prediction = predictions.get(
                    name
                )


                prediction_valid = (

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


                if not prediction_valid:

                    predictions_valid[
                        name
                    ] = False


                else:

                    normalized_predictions[
                        name
                    ] = prediction


            normalized_rows.append({

                "label":
                    label,

                "slice":
                    slice_name,

                "predictions":
                    normalized_predictions,
            })


    else:

        for name in submitted_names:

            predictions_valid[
                name
            ] = False


    # =====================================================
    # RESULT ORDER
    # =====================================================

    order_index = {}


    if policy_valid:

        order_index = {

            name:
                index

            for (
                index,
                name
            ) in enumerate(
                policy[
                    "candidateOrder"
                ]
            )
        }


    def result_candidate_sort_key(
        candidate
    ):

        name = candidate.get(
            "name"
        )


        if (
            policy_valid
            and name in order_index
        ):

            return (
                0,
                order_index[
                    name
                ],
                b"",
            )


        return (
            1,
            0,
            (
                name.encode("utf-8")
                if isinstance(
                    name,
                    str
                )
                else b""
            ),
        )


    candidates_for_results = sorted(
        submitted_candidates,
        key=result_candidate_sort_key
    )


    results = []


    # Map for winner selection.
    result_map = {}


    # =====================================================
    # EVALUATE EACH CANDIDATE
    # =====================================================

    for candidate in candidates_for_results:

        name = candidate.get(
            "name"
        )


        codes = []


        # -------------------------------------------------
        # Frozen status
        # -------------------------------------------------

        if candidate.get(
            "status"
        ) != "frozen":

            codes.append(
                "NOT_FROZEN"
            )


        # -------------------------------------------------
        # Exact frozen lineage
        # -------------------------------------------------

        if not lineage_valid:

            codes.append(
                "INVALID_LINEAGE"
            )


        # -------------------------------------------------
        # Policy
        # -------------------------------------------------

        if (
            not policy_valid
            or not candidate_order_set_valid
        ):

            codes.append(
                "INVALID_POLICY"
            )


        # -------------------------------------------------
        # Manifest
        # -------------------------------------------------

        (
            manifest_valid,
            recomputed_total,
            recomputed_digest,
        ) = quant_verify_manifest(
            candidate
        )


        if not manifest_valid:

            codes.append(
                "INVALID_MANIFEST"
            )


        total_bytes = (

            recomputed_total

            if manifest_valid

            else None
        )


        # -------------------------------------------------
        # Prediction validation
        # -------------------------------------------------

        candidate_predictions_valid = (
            predictions_valid.get(
                name,
                False
            )
        )


        if not candidate_predictions_valid:

            codes.append(
                "INVALID_PREDICTIONS"
            )


        # -------------------------------------------------
        # Latency validation
        # -------------------------------------------------

        latency_value = None


        if (
            latency_container_valid
            and name in latencies
            and quant_is_nonnegative_finite(
                latencies.get(
                    name
                )
            )
        ):

            latency_value = float(
                latencies[
                    name
                ]
            )


        else:

            codes.append(
                "INVALID_POLICY"
            )


        # -------------------------------------------------
        # Metrics
        # -------------------------------------------------

        aggregate = None

        slice_results = {}


        if candidate_predictions_valid:


            # ---------------------------------------------
            # Aggregate accuracy
            # ---------------------------------------------

            # Empty rows naturally cannot establish
            # a valid aggregate prediction metric.
            if len(rows) == 0:

                codes.append(
                    "INVALID_PREDICTIONS"
                )


            else:

                correct = sum(

                    1

                    for row
                    in normalized_rows

                    if (
                        row[
                            "predictions"
                        ].get(name)
                        == row[
                            "label"
                        ]
                    )
                )


                aggregate = round(
                    correct
                    / len(rows),
                    12
                )


                # -----------------------------------------
                # Aggregate floor
                # -----------------------------------------

                if (
                    policy_valid
                    and aggregate
                    < policy[
                        "aggregateFloor"
                    ]
                ):

                    codes.append(
                        "AGGREGATE_FLOOR"
                    )


                # -----------------------------------------
                # Required slices
                # -----------------------------------------

                if policy_valid:

                    for (
                        slice_name,
                        floor
                    ) in policy[
                        "requiredSlices"
                    ].items():


                        matching = [

                            row

                            for row
                            in normalized_rows

                            if (
                                row[
                                    "slice"
                                ]
                                == slice_name
                            )
                        ]


                        if len(matching) == 0:

                            slice_results[
                                slice_name
                            ] = None


                            codes.append(
                                "MISSING_SLICE:"
                                + slice_name
                            )


                            continue


                        slice_correct = sum(

                            1

                            for row
                            in matching

                            if (
                                row[
                                    "predictions"
                                ].get(
                                    name
                                )
                                == row[
                                    "label"
                                ]
                            )
                        )


                        slice_accuracy = round(
                            slice_correct
                            / len(matching),
                            12
                        )


                        slice_results[
                            slice_name
                        ] = (
                            slice_accuracy
                        )


                        if (
                            slice_accuracy
                            < floor
                        ):

                            codes.append(
                                "SLICE_FLOOR:"
                                + slice_name
                            )


        # -------------------------------------------------
        # Invalid predictions:
        #
        # aggregate AND required slice values must be null.
        # -------------------------------------------------

        if not candidate_predictions_valid:

            aggregate = None


            if policy_valid:

                slice_results = {

                    slice_name:
                        None

                    for slice_name
                    in policy[
                        "requiredSlices"
                    ].keys()
                }

            else:

                slice_results = {}


        # -------------------------------------------------
        # Size limit
        # -------------------------------------------------

        if (
            policy_valid
            and total_bytes is not None
            and total_bytes
            > policy[
                "maxBytes"
            ]
        ):

            codes.append(
                "SIZE_LIMIT"
            )


        # -------------------------------------------------
        # Latency limit
        # -------------------------------------------------

        if (
            policy_valid
            and latency_value is not None
            and latency_value
            > policy[
                "maxLatencyMs"
            ]
        ):

            codes.append(
                "LATENCY_LIMIT"
            )


        codes = quant_sort_codes(
            codes
        )


        admitted = (
            codes == []
        )


        result = {

            "name":
                name,

            "aggregate":
                aggregate,

            "slices":
                slice_results,

            "totalBytes":
                total_bytes,

            "latencyMs":
                latency_value,

            "admitted":
                admitted,

            "reasonCodes":
                codes,
        }


        results.append(
            result
        )


        if isinstance(
            name,
            str
        ):

            result_map[
                name
            ] = result


        audit(
            request_id,
            "QUANTIZE_SELECT_CANDIDATE",
            {
                "name":
                    name,

                "lineageValid":
                    lineage_valid,

                "manifestValid":
                    manifest_valid,

                "recomputedPackageDigest":
                    recomputed_digest,

                "predictionsValid":
                    candidate_predictions_valid,

                "result":
                    result,
            }
        )


    # =====================================================
    # WINNER SELECTION
    # =====================================================

    admitted_names = [

        result[
            "name"
        ]

        for result in results

        if result[
            "admitted"
        ]
        and isinstance(
            result[
                "name"
            ],
            str
        )
    ]


    selected = None


    if admitted_names:


        def winner_key(name):

            result = result_map[
                name
            ]


            # Candidate order is final tie-breaker.
            candidate_rank = (
                order_index.get(
                    name,
                    SAFE_INTEGER_MAX
                )
            )


            return (

                # Smaller package.
                result[
                    "totalBytes"
                ],

                # Lower latency.
                result[
                    "latencyMs"
                ],

                # Then candidateOrder.
                candidate_rank,

                # UTF-8 fallback.
                name.encode(
                    "utf-8"
                ),
            )


        selected = min(
            admitted_names,
            key=winner_key
        )


    # =====================================================
    # PACKAGE MANIFEST
    # =====================================================

    package_manifest = None


    if (
        selected is not None
        and stored_candidates
        is not None
    ):

        for frozen_candidate in (
            stored_candidates
        ):

            if (
                frozen_candidate.get(
                    "name"
                )
                == selected
            ):

                # Exactly the recorded winner object.
                package_manifest = (
                    frozen_candidate
                )

                break


    # =====================================================
    # EXACT SELECT RESPONSE
    # =====================================================

    response = {

        "freezeId":
            freeze_id,

        "selected":
            selected,

        "results":
            results,

        "packageManifest":
            package_manifest,
    }


    audit(
        request_id,
        "QUANTIZE_SELECT_RESPONSE",
        {
            "lineageValid":
                lineage_valid,

            "policyValid":
                policy_valid,

            "candidateOrderSetValid":
                candidate_order_set_valid,

            "response":
                response,
        }
    )


    return response


# =========================================================
# MAIN /quantize ENDPOINT
# =========================================================

@app.post("/quantize")
async def quantize_endpoint(
    request: Request
):

    request_id = (
        uuid.uuid4().hex[:8]
    )


    # -----------------------------------------------------
    # Strict JSON
    # -----------------------------------------------------

    try:

        raw_body = await request.body()


        audit(
            request_id,
            "QUANTIZE_HTTP_REQUEST",
            {
                "contentType":
                    request.headers.get(
                        "content-type"
                    ),

                "rawBody":
                    repr(
                        raw_body
                    ),
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
            "QUANTIZE_PARSE_FAILED",
            {
                "type":
                    type(
                        exc
                    ).__name__,

                "message":
                    str(
                        exc
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


    audit(
        request_id,
        "QUANTIZE_REQUEST_PARSED",
        body
    )


    # -----------------------------------------------------
    # Body must be object.
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


    phase = body.get(
        "phase"
    )


    # -----------------------------------------------------
    # Unknown / missing phase
    # -----------------------------------------------------

    if phase not in (
        "freeze",
        "select",
    ):

        audit(
            request_id,
            "QUANTIZE_INVALID_PHASE",
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
    # FREEZE
    # =====================================================

    if phase == "freeze":


        # Explicit requirement:
        #
        # empty/non-array candidate list -> HTTP 400.
        candidates = body.get(
            "candidates"
        )


        if (
            not isinstance(
                candidates,
                list
            )
            or len(
                candidates
            ) == 0
        ):

            audit(
                request_id,
                "QUANTIZE_FREEZE_TOP_LEVEL_INVALID",
                {
                    "candidatesType":
                        type(
                            candidates
                        ).__name__,

                    "candidateCount":
                        (
                            len(candidates)
                            if isinstance(
                                candidates,
                                list
                            )
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


        freeze_id = body.get(
            "freezeId"
        )


        freeze_id_valid = (

            quant_is_nonempty_utf8_string(
                freeze_id
            )

            and len(
                freeze_id
            ) <= 128
        )


        fingerprint = (
            quant_freeze_fingerprint(
                body
            )
        )


        # ---------------------------------------------
        # Existing valid freezeId
        # ---------------------------------------------

        if (
            freeze_id_valid
            and freeze_id
            in QUANTIZE_FREEZE_STORE
        ):

            stored = (
                QUANTIZE_FREEZE_STORE[
                    freeze_id
                ]
            )


            # Identical replay.
            if (
                stored[
                    "fingerprint"
                ]
                == fingerprint
            ):

                audit(
                    request_id,
                    "QUANTIZE_FREEZE_REPLAY",
                    {
                        "freezeId":
                            freeze_id,

                        "response":
                            stored[
                                "response"
                            ],
                    }
                )


                return stored[
                    "response"
                ]


            # Same ID, different freeze.
            audit(
                request_id,
                "QUANTIZE_FREEZE_CONFLICT",
                {
                    "freezeId":
                        freeze_id
                }
            )


            return JSONResponse(
                status_code=409,
                content={
                    "error":
                        "FREEZE_ID_CONFLICT"
                }
            )


        # ---------------------------------------------
        # New freeze
        # ---------------------------------------------

        (
            response,
            can_store,
        ) = quant_process_freeze(
            body,
            request_id
        )


        # A malformed freezeId cannot reserve state.
        if can_store:

            QUANTIZE_FREEZE_STORE[
                freeze_id
            ] = {

                "fingerprint":
                    fingerprint,

                "response":
                    response,
            }


            audit(
                request_id,
                "QUANTIZE_FREEZE_STORED",
                {
                    "freezeId":
                        freeze_id,

                    "response":
                        response,
                }
            )


        return response


    # =====================================================
    # SELECT
    # =====================================================

    # Explicit requirement:
    #
    # select needs:
    # - candidates array
    # - rows array
    # - policy object
    #
    # otherwise HTTP 400.
    if (
        not isinstance(
            body.get(
                "candidates"
            ),
            list
        )

        or not isinstance(
            body.get(
                "rows"
            ),
            list
        )

        or not isinstance(
            body.get(
                "policy"
            ),
            dict
        )
    ):

        audit(
            request_id,
            "QUANTIZE_SELECT_TOP_LEVEL_INVALID",
            {
                "candidatesType":
                    type(
                        body.get(
                            "candidates"
                        )
                    ).__name__,

                "rowsType":
                    type(
                        body.get(
                            "rows"
                        )
                    ).__name__,

                "policyType":
                    type(
                        body.get(
                            "policy"
                        )
                    ).__name__,
            }
        )


        return JSONResponse(
            status_code=400,
            content={
                "error":
                    "INVALID_INPUT"
            }
        )


    return quant_process_select(
        body,
        request_id
    )

# =========================================================
# WEEK 8 - Q6
# Recover a Content-Addressed ML Pipeline
# Endpoint: POST /pipeline
# =========================================================

import copy


# =========================================================
# FIXED PIPELINE DAG
# =========================================================

PIPELINE_NODES = [
    "verify_data",
    "prepare",
    "train",
    "evaluate",
    "register",
    "publish",
]


PIPELINE_EVENT_FIELDS = {
    "eventId",
    "revision",
    "node",
    "attempt",
    "status",
    "key",
    "artifactDigest",
    "receiptId",
}


PIPELINE_STATUSES = {
    "started",
    "succeeded",
    "retryable_failed",
    "terminal_failed",
}


# All required input fields.
PIPELINE_REQUIRED_INPUTS = [
    "generation",
    "checksum",
    "canonicalData",
    "prepareCode",
    "prepareConfig",
    "trainCode",
    "trainConfig",
    "runtime",
    "evaluateCode",
    "evaluateConfig",
    "schemaDigest",
    "publishConfig",
]


# =========================================================
# STATE STORE
# =========================================================
#
# State is isolated by session.
#
# Example:
#
# PIPELINE_SESSIONS["session-a"] = {
#     "revision": 1,
#     "inputs": {...},
#     "inputsFingerprint": "...",
#
#     "nodeStates": {
#         "train": {
#             "status": "started",
#             "attempt": 1,
#             "key": "...",
#             "eventId": "event-3"
#         }
#     },
#
#     "cache": {
#         "train": {
#             "<cache-key>": {
#                 "artifactDigest": "...",
#                 "eventId": "..."
#             }
#         }
#     },
#
#     "eventLedger": {
#         "event-1": "<canonical event json>"
#     }
# }
#
# Cache and event IDs survive revisions.
#
PIPELINE_SESSIONS = {}


# =========================================================
# BASIC HELPERS
# =========================================================

def pipeline_is_safe_positive_int(value):
    """
    Positive JavaScript-safe integer.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= SAFE_INTEGER_MAX
    )


def pipeline_is_utf8_string(value):
    """
    Valid UTF-8 string.
    """

    if not isinstance(value, str):
        return False

    try:
        value.encode("utf-8")
        return True

    except UnicodeEncodeError:
        return False


def pipeline_is_nonempty_string(value):
    """
    Non-empty UTF-8 string.
    """

    return (
        pipeline_is_utf8_string(value)
        and value != ""
    )


# =========================================================
# HASH HELPERS
# =========================================================

def pipeline_hash_array(values):
    """
    Compute:

    lowercase SHA-256(
        UTF8(
            compact JSON array
        )
    )

    Exact value order is supplied by the caller.
    """

    serialized = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":")
    )


    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def pipeline_inputs_fingerprint(inputs):
    """
    Used ONLY for revision conflict detection.

    All input fields matter, including extra metadata.

    Object key order does not matter.
    """

    serialized = json.dumps(
        inputs,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )


    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


# =========================================================
# CANONICAL EVENT REPRESENTATION
# =========================================================

def pipeline_canonical_event(event):
    """
    Canonical event JSON with the exact eight fields
    in the published order.

    Used for global eventId replay/conflict detection.
    """

    canonical_object = {

        "eventId":
            event.get("eventId"),

        "revision":
            event.get("revision"),

        "node":
            event.get("node"),

        "attempt":
            event.get("attempt"),

        "status":
            event.get("status"),

        "key":
            event.get("key"),

        "artifactDigest":
            event.get("artifactDigest"),

        "receiptId":
            event.get("receiptId"),
    }


    return json.dumps(
        canonical_object,
        ensure_ascii=False,
        separators=(",", ":")
    )


# =========================================================
# REQUEST VALIDATION
# =========================================================

def pipeline_validate_request(body):
    """
    Validate the main request contract.

    Returns:
        True / False
    """

    if not isinstance(body, dict):
        return False


    # -----------------------------------------------------
    # session
    # -----------------------------------------------------

    session = body.get(
        "session"
    )


    if not pipeline_is_nonempty_string(
        session
    ):
        return False


    # -----------------------------------------------------
    # revision
    # -----------------------------------------------------

    revision = body.get(
        "revision"
    )


    if not pipeline_is_safe_positive_int(
        revision
    ):
        return False


    # -----------------------------------------------------
    # inputs
    # -----------------------------------------------------

    inputs = body.get(
        "inputs"
    )


    if not isinstance(
        inputs,
        dict
    ):
        return False


    # All 12 required fields must be non-empty strings.
    for field in PIPELINE_REQUIRED_INPUTS:

        if field not in inputs:
            return False


        if not pipeline_is_nonempty_string(
            inputs[
                field
            ]
        ):
            return False


    # Extra metadata is explicitly allowed.


    # -----------------------------------------------------
    # events
    # -----------------------------------------------------

    events = body.get(
        "events"
    )


    if not isinstance(
        events,
        list
    ):
        return False


    return True


# =========================================================
# SESSION CREATION
# =========================================================

def pipeline_new_session_state(
    revision,
    inputs
):
    """
    Create a fresh session state.
    """

    return {

        "revision":
            revision,

        "inputs":
            copy.deepcopy(
                inputs
            ),

        "inputsFingerprint":
            pipeline_inputs_fingerprint(
                inputs
            ),

        # Current revision's attempt/terminal states.
        "nodeStates": {},

        # Successful content-addressed cache survives
        # across revisions.
        "cache": {
            node: {}
            for node in PIPELINE_NODES
        },

        # Accepted event IDs survive across revisions.
        "eventLedger": {},
    }


# =========================================================
# CURRENT CACHE KEYS + DEPENDENCIES
# =========================================================

def pipeline_compute_keys_and_dependencies(
    state
):
    """
    Compute all currently available cache keys.

    Important rule:

        downstream key = null
        until parent is reusable from cache.

    Returns:

        keys = {
            node: key-or-None
        }

        dependencies = {
            node: {...}
        }
    """

    inputs = state[
        "inputs"
    ]

    cache = state[
        "cache"
    ]


    keys = {}

    dependencies = {}


    # =====================================================
    # verify_data
    #
    # [generation, checksum]
    # =====================================================

    verify_key = pipeline_hash_array([
        inputs[
            "generation"
        ],
        inputs[
            "checksum"
        ],
    ])


    keys[
        "verify_data"
    ] = verify_key


    dependencies[
        "verify_data"
    ] = {

        "generation":
            inputs[
                "generation"
            ],

        "checksum":
            inputs[
                "checksum"
            ],

        "cacheKey":
            verify_key,
    }


    # =====================================================
    # prepare
    #
    # [canonicalData, prepareCode, prepareConfig]
    #
    # But key is unavailable until verify_data
    # is reusable.
    # =====================================================

    verify_cache_entry = (
        cache[
            "verify_data"
        ].get(
            verify_key
        )
    )


    if verify_cache_entry is not None:

        prepare_key = pipeline_hash_array([
            inputs[
                "canonicalData"
            ],
            inputs[
                "prepareCode"
            ],
            inputs[
                "prepareConfig"
            ],
        ])

    else:

        prepare_key = None


    keys[
        "prepare"
    ] = prepare_key


    dependencies[
        "prepare"
    ] = {

        "canonicalData":
            inputs[
                "canonicalData"
            ],

        "prepareCode":
            inputs[
                "prepareCode"
            ],

        "prepareConfig":
            inputs[
                "prepareConfig"
            ],

        "cacheKey":
            prepare_key,
    }


    # =====================================================
    # train
    #
    # [prepareArtifact, trainCode, trainConfig, runtime]
    # =====================================================

    prepare_artifact = None


    if prepare_key is not None:

        prepare_cache_entry = (
            cache[
                "prepare"
            ].get(
                prepare_key
            )
        )

        if (
            prepare_cache_entry
            is not None
        ):

            prepare_artifact = (
                prepare_cache_entry[
                    "artifactDigest"
                ]
            )


    if prepare_artifact is not None:

        train_key = pipeline_hash_array([
            prepare_artifact,
            inputs[
                "trainCode"
            ],
            inputs[
                "trainConfig"
            ],
            inputs[
                "runtime"
            ],
        ])

    else:

        train_key = None


    keys[
        "train"
    ] = train_key


    dependencies[
        "train"
    ] = {

        "prepareArtifact":
            prepare_artifact,

        "trainCode":
            inputs[
                "trainCode"
            ],

        "trainConfig":
            inputs[
                "trainConfig"
            ],

        "runtime":
            inputs[
                "runtime"
            ],

        "cacheKey":
            train_key,
    }


    # =====================================================
    # evaluate
    #
    # [
    #   trainArtifact,
    #   canonicalData,
    #   evaluateCode,
    #   evaluateConfig
    # ]
    # =====================================================

    train_artifact = None


    if train_key is not None:

        train_cache_entry = (
            cache[
                "train"
            ].get(
                train_key
            )
        )


        if (
            train_cache_entry
            is not None
        ):

            train_artifact = (
                train_cache_entry[
                    "artifactDigest"
                ]
            )


    if train_artifact is not None:

        evaluate_key = pipeline_hash_array([
            train_artifact,
            inputs[
                "canonicalData"
            ],
            inputs[
                "evaluateCode"
            ],
            inputs[
                "evaluateConfig"
            ],
        ])

    else:

        evaluate_key = None


    keys[
        "evaluate"
    ] = evaluate_key


    dependencies[
        "evaluate"
    ] = {

        "trainArtifact":
            train_artifact,

        "canonicalData":
            inputs[
                "canonicalData"
            ],

        "evaluateCode":
            inputs[
                "evaluateCode"
            ],

        "evaluateConfig":
            inputs[
                "evaluateConfig"
            ],

        "cacheKey":
            evaluate_key,
    }


    # =====================================================
    # register
    #
    # [evaluateArtifact, schemaDigest]
    # =====================================================

    evaluate_artifact = None


    if evaluate_key is not None:

        evaluate_cache_entry = (
            cache[
                "evaluate"
            ].get(
                evaluate_key
            )
        )


        if (
            evaluate_cache_entry
            is not None
        ):

            evaluate_artifact = (
                evaluate_cache_entry[
                    "artifactDigest"
                ]
            )


    if evaluate_artifact is not None:

        register_key = pipeline_hash_array([
            evaluate_artifact,
            inputs[
                "schemaDigest"
            ],
        ])

    else:

        register_key = None


    keys[
        "register"
    ] = register_key


    dependencies[
        "register"
    ] = {

        "evaluateArtifact":
            evaluate_artifact,

        "schemaDigest":
            inputs[
                "schemaDigest"
            ],

        "cacheKey":
            register_key,
    }


    # =====================================================
    # publish
    #
    # [registerArtifact, publishConfig]
    # =====================================================

    register_artifact = None


    if register_key is not None:

        register_cache_entry = (
            cache[
                "register"
            ].get(
                register_key
            )
        )


        if (
            register_cache_entry
            is not None
        ):

            register_artifact = (
                register_cache_entry[
                    "artifactDigest"
                ]
            )


    if register_artifact is not None:

        publish_key = pipeline_hash_array([
            register_artifact,
            inputs[
                "publishConfig"
            ],
        ])

    else:

        publish_key = None


    keys[
        "publish"
    ] = publish_key


    dependencies[
        "publish"
    ] = {

        "registerArtifact":
            register_artifact,

        "publishConfig":
            inputs[
                "publishConfig"
            ],

        "cacheKey":
            publish_key,
    }


    return (
        keys,
        dependencies,
    )


# =========================================================
# EVENT STRUCTURE VALIDATION
# =========================================================

def pipeline_event_shape_valid(event):
    """
    INVALID_EVENT is reserved for a malformed
    event object itself.

    Semantic problems such as:
    - wrong node
    - wrong key
    - invalid status
    - bad attempt
    - bad receipt

    are ignored instead, as required.
    """

    if not isinstance(
        event,
        dict
    ):
        return False


    # EXACTLY eight listed fields.
    if set(
        event.keys()
    ) != PIPELINE_EVENT_FIELDS:

        return False


    # eventId itself must be a usable global ID.
    if not pipeline_is_nonempty_string(
        event.get(
            "eventId"
        )
    ):

        return False


    return True


# =========================================================
# SEMANTIC EVENT VALIDATION
# =========================================================

def pipeline_event_semantically_valid(
    event,
    state,
    current_keys
):
    """
    Returns:

        (
            True,
            current_key
        )

    when the event is processable.

    Returns:

        (
            False,
            None
        )

    for events that the specification says to IGNORE.
    """


    current_revision = (
        state[
            "revision"
        ]
    )


    event_revision = event.get(
        "revision"
    )


    # -----------------------------------------------------
    # Wrong or malformed revision -> ignore.
    # -----------------------------------------------------

    if not pipeline_is_safe_positive_int(
        event_revision
    ):

        return False, None


    if (
        event_revision
        != current_revision
    ):

        return False, None


    # -----------------------------------------------------
    # Node
    # -----------------------------------------------------

    node = event.get(
        "node"
    )


    if node not in PIPELINE_NODES:

        return False, None


    # -----------------------------------------------------
    # Attempt
    # -----------------------------------------------------

    attempt = event.get(
        "attempt"
    )


    if not pipeline_is_safe_positive_int(
        attempt
    ):

        return False, None


    # -----------------------------------------------------
    # Status
    # -----------------------------------------------------

    status = event.get(
        "status"
    )


    if status not in PIPELINE_STATUSES:

        return False, None


    # -----------------------------------------------------
    # Node must currently be ready.
    #
    # If parent is not reusable, key is null.
    # -----------------------------------------------------

    current_key = (
        current_keys.get(
            node
        )
    )


    if current_key is None:

        return False, None


    # -----------------------------------------------------
    # Event key must be the current key.
    # -----------------------------------------------------

    supplied_key = event.get(
        "key"
    )


    if (
        not pipeline_is_nonempty_string(
            supplied_key
        )
        or supplied_key
        != current_key
    ):

        return False, None


    artifact_digest = event.get(
        "artifactDigest"
    )


    receipt_id = event.get(
        "receiptId"
    )


    # =====================================================
    # Artifact rules
    # =====================================================

    if status == "succeeded":

        # Success requires a non-empty artifact.
        if not pipeline_is_nonempty_string(
            artifact_digest
        ):

            return False, None


    else:

        # Every non-success event requires null artifact.
        if artifact_digest is not None:

            return False, None


    # =====================================================
    # Receipt rules
    # =====================================================

    if (
        status == "succeeded"
        and node in (
            "register",
            "publish",
        )
    ):

        expected_receipt = (
            "receipt:"
            + node
            + ":"
            + current_key
        )


        if receipt_id != expected_receipt:

            return False, None


    else:

        # Every other event requires null receipt.
        if receipt_id is not None:

            return False, None


    return (
        True,
        current_key,
    )


# =========================================================
# ACCEPT EVENT
# =========================================================

def pipeline_accept_event(
    state,
    event,
    canonical_event,
    current_key
):
    """
    Permanently consume one accepted event ID and update
    current state/cache.

    The caller works on a copied session, so all mutations
    remain atomic until the whole batch succeeds.
    """

    event_id = event[
        "eventId"
    ]

    node = event[
        "node"
    ]

    attempt = event[
        "attempt"
    ]

    status = event[
        "status"
    ]


    # Event ID is now consumed globally in this session.
    state[
        "eventLedger"
    ][
        event_id
    ] = canonical_event


    # -----------------------------------------------------
    # started
    # -----------------------------------------------------

    if status == "started":

        state[
            "nodeStates"
        ][
            node
        ] = {

            "status":
                "started",

            "attempt":
                attempt,

            "key":
                current_key,

            "eventId":
                event_id,
        }


    # -----------------------------------------------------
    # retryable failure
    # -----------------------------------------------------

    elif status == "retryable_failed":

        state[
            "nodeStates"
        ][
            node
        ] = {

            "status":
                "retryable_failed",

            "attempt":
                attempt,

            "key":
                current_key,

            "eventId":
                event_id,
        }


    # -----------------------------------------------------
    # terminal failure
    # -----------------------------------------------------

    elif status == "terminal_failed":

        state[
            "nodeStates"
        ][
            node
        ] = {

            "status":
                "terminal_failed",

            "attempt":
                attempt,

            "key":
                current_key,

            "eventId":
                event_id,
        }


    # -----------------------------------------------------
    # success
    # -----------------------------------------------------

    elif status == "succeeded":

        artifact_digest = (
            event[
                "artifactDigest"
            ]
        )


        # Permanently bind this key to its first
        # artifact and event ID.
        state[
            "cache"
        ][
            node
        ][
            current_key
        ] = {

            "artifactDigest":
                artifact_digest,

            "eventId":
                event_id,
        }


        state[
            "nodeStates"
        ][
            node
        ] = {

            "status":
                "succeeded",

            "attempt":
                attempt,

            "key":
                current_key,

            "eventId":
                event_id,
        }


# =========================================================
# PROCESS ONE EVENT
# =========================================================

def pipeline_process_event(
    state,
    event
):
    """
    Return:

        ("accept", None)

        ("ignore", None)

        ("conflict", "EVENT_ID_CONFLICT")
        ("conflict", "EVIDENCE_CONFLICT")
        ("conflict", "STATUS_CONFLICT")
        ("conflict", "INVALID_EVENT")
    """


    # =====================================================
    # 1. Event must have the exact required shape.
    # =====================================================

    if not pipeline_event_shape_valid(
        event
    ):

        return (
            "conflict",
            "INVALID_EVENT",
        )


    event_id = event[
        "eventId"
    ]


    canonical_event = (
        pipeline_canonical_event(
            event
        )
    )


    # =====================================================
    # 2. Global event ID replay/conflict
    # =====================================================

    existing_event = (
        state[
            "eventLedger"
        ].get(
            event_id
        )
    )


    if existing_event is not None:


        # Exact replay is ignored.
        if (
            existing_event
            == canonical_event
        ):

            return (
                "ignore",
                None,
            )


        # Same consumed ID with different event evidence.
        return (
            "conflict",
            "EVENT_ID_CONFLICT",
        )


    # =====================================================
    # 3. Recompute current keys before EVERY event.
    #
    # An earlier event in this same batch may have
    # successfully unlocked the next DAG node.
    # =====================================================

    (
        current_keys,
        _
    ) = pipeline_compute_keys_and_dependencies(
        state
    )


    (
        semantic_valid,
        current_key
    ) = pipeline_event_semantically_valid(
        event,
        state,
        current_keys
    )


    # Wrong revision/node/key, unavailable parent,
    # invalid attempt/status/artifact/receipt => IGNORE.
    #
    # Ignored events DO NOT consume event IDs.
    if not semantic_valid:

        return (
            "ignore",
            None,
        )


    node = event[
        "node"
    ]

    attempt = event[
        "attempt"
    ]

    status = event[
        "status"
    ]


    # =====================================================
    # 4. Existing immutable cache
    # =====================================================

    cache_entry = (
        state[
            "cache"
        ][
            node
        ].get(
            current_key
        )
    )


    if cache_entry is not None:


        # A new success with different immutable evidence
        # is an evidence conflict.
        if (
            status == "succeeded"

            and event[
                "artifactDigest"
            ]
            != cache_entry[
                "artifactDigest"
            ]
        ):

            return (
                "conflict",
                "EVIDENCE_CONFLICT",
            )


        # Any other NEW valid event after success conflicts.
        #
        # Exact replay was already handled above.
        return (
            "conflict",
            "STATUS_CONFLICT",
        )


    # =====================================================
    # 5. Current non-cached node state
    # =====================================================

    previous = (
        state[
            "nodeStates"
        ].get(
            node
        )
    )


    # Defensive protection:
    # only a state for this exact current key matters.
    if (
        previous is not None
        and previous.get(
            "key"
        )
        != current_key
    ):

        previous = None


    # =====================================================
    # CASE A: no state
    # =====================================================

    if previous is None:


        # Only started(1) is accepted.
        if (
            status == "started"
            and attempt == 1
        ):

            pipeline_accept_event(
                state,
                event,
                canonical_event,
                current_key
            )

            return (
                "accept",
                None,
            )


        # Completion without start, or attempt > 1,
        # is ignored.
        return (
            "ignore",
            None,
        )


    previous_status = (
        previous[
            "status"
        ]
    )

    previous_attempt = (
        previous[
            "attempt"
        ]
    )


    # =====================================================
    # CASE B: terminal_failed
    #
    # Any NEW valid event is a STATUS_CONFLICT.
    # =====================================================

    if (
        previous_status
        == "terminal_failed"
    ):

        return (
            "conflict",
            "STATUS_CONFLICT",
        )


    # =====================================================
    # CASE C: started(n)
    # =====================================================

    if previous_status == "started":


        # Lower attempt is stale -> ignore.
        if attempt < previous_attempt:

            return (
                "ignore",
                None,
            )


        # Completion on exactly the same attempt.
        if (
            attempt == previous_attempt

            and status in (
                "succeeded",
                "retryable_failed",
                "terminal_failed",
            )
        ):

            pipeline_accept_event(
                state,
                event,
                canonical_event,
                current_key
            )

            return (
                "accept",
                None,
            )


        # Any other transition conflicts.
        return (
            "conflict",
            "STATUS_CONFLICT",
        )


    # =====================================================
    # CASE D: retryable_failed(n)
    # =====================================================

    if (
        previous_status
        == "retryable_failed"
    ):


        # Lower attempt is stale.
        if attempt < previous_attempt:

            return (
                "ignore",
                None,
            )


        # Only started(n+1) is allowed.
        if (
            status == "started"

            and attempt
            == previous_attempt + 1
        ):

            pipeline_accept_event(
                state,
                event,
                canonical_event,
                current_key
            )

            return (
                "accept",
                None,
            )


        return (
            "conflict",
            "STATUS_CONFLICT",
        )


    # =====================================================
    # succeeded state should always have matching cache.
    # If somehow reached, conservatively conflict.
    # =====================================================

    return (
        "conflict",
        "STATUS_CONFLICT",
    )


# =========================================================
# BUILD FINAL NODE RESPONSE
# =========================================================

def pipeline_build_nodes(state):
    """
    Build node decisions in fixed DAG order.

    Every node gets EXACTLY one reason code.
    """

    (
        keys,
        dependencies
    ) = pipeline_compute_keys_and_dependencies(
        state
    )


    output_nodes = []


    # Used to propagate pending/terminal reason
    # and triggering IDs downstream.
    previous_result = None


    for node in PIPELINE_NODES:

        current_key = (
            keys[
                node
            ]
        )


        # =================================================
        # Parent unavailable
        # =================================================

        if current_key is None:


            # First node can never have null key.
            if previous_result is not None:


                if (
                    previous_result[
                        "reasonCodes"
                    ][0]
                    in (
                        "TERMINAL_FAILURE",
                        "UPSTREAM_TERMINAL",
                    )
                ):

                    reason = (
                        "UPSTREAM_TERMINAL"
                    )


                else:

                    reason = (
                        "UPSTREAM_PENDING"
                    )


                triggering_ids = []


            else:

                reason = (
                    "UPSTREAM_PENDING"
                )

                triggering_ids = []


            result = {

                "node":
                    node,

                "action":
                    "block",

                "reasonCodes":
                    [
                        reason
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                "triggeringEventIds":
                    triggering_ids,
            }


            output_nodes.append(
                result
            )


            previous_result = result

            continue


        # =================================================
        # Cache hit
        # =================================================

        cache_entry = (
            state[
                "cache"
            ][
                node
            ].get(
                current_key
            )
        )


        if cache_entry is not None:

            result = {

                "node":
                    node,

                "action":
                    "reuse",

                "reasonCodes":
                    [
                        "CACHE_HIT"
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                # Immutable original success event.
                "triggeringEventIds":
                    [
                        cache_entry[
                            "eventId"
                        ]
                    ],
            }


            output_nodes.append(
                result
            )


            previous_result = result

            continue


        # =================================================
        # Current state for this key
        # =================================================

        state_entry = (
            state[
                "nodeStates"
            ].get(
                node
            )
        )


        if (
            state_entry is not None

            and state_entry.get(
                "key"
            )
            != current_key
        ):

            state_entry = None


        # -------------------------------------------------
        # Running
        # -------------------------------------------------

        if (
            state_entry is not None

            and state_entry[
                "status"
            ] == "started"
        ):

            result = {

                "node":
                    node,

                "action":
                    "block",

                "reasonCodes":
                    [
                        "RUNNING"
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                "triggeringEventIds":
                    [
                        state_entry[
                            "eventId"
                        ]
                    ],
            }


        # -------------------------------------------------
        # Retryable failure
        # -------------------------------------------------

        elif (
            state_entry is not None

            and state_entry[
                "status"
            ]
            == "retryable_failed"
        ):

            result = {

                "node":
                    node,

                "action":
                    "rerun",

                "reasonCodes":
                    [
                        "RETRYABLE_FAILURE"
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                "triggeringEventIds":
                    [
                        state_entry[
                            "eventId"
                        ]
                    ],
            }


        # -------------------------------------------------
        # Terminal failure
        # -------------------------------------------------

        elif (
            state_entry is not None

            and state_entry[
                "status"
            ]
            == "terminal_failed"
        ):

            result = {

                "node":
                    node,

                "action":
                    "block",

                "reasonCodes":
                    [
                        "TERMINAL_FAILURE"
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                "triggeringEventIds":
                    [
                        state_entry[
                            "eventId"
                        ]
                    ],
            }


        # -------------------------------------------------
        # Ready but no cache/state
        # -------------------------------------------------

        else:

            result = {

                "node":
                    node,

                "action":
                    "rerun",

                "reasonCodes":
                    [
                        "CACHE_MISS"
                    ],

                "dependencyDigests":
                    dependencies[
                        node
                    ],

                "triggeringEventIds":
                    [],
            }


        output_nodes.append(
            result
        )


        previous_result = result


    return output_nodes


# =========================================================
# MAIN /pipeline ENDPOINT
# =========================================================

@app.post("/pipeline")
async def pipeline_endpoint(
    request: Request
):

    request_id = (
        uuid.uuid4().hex[:8]
    )


    # =====================================================
    # 1. STRICT JSON PARSING
    # =====================================================

    try:

        raw_body = await request.body()


        audit(
            request_id,
            "PIPELINE_HTTP_REQUEST",
            {
                "contentType":
                    request.headers.get(
                        "content-type"
                    ),

                "rawBody":
                    repr(
                        raw_body
                    ),
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
            "PIPELINE_PARSE_FAILED",
            {
                "type":
                    type(
                        exc
                    ).__name__,

                "message":
                    str(
                        exc
                    ),
            }
        )


        # Q6 defines all controller errors as HTTP 409.
        return JSONResponse(
            status_code=409,
            content={
                "error":
                    "INVALID_REQUEST"
            }
        )


    # =====================================================
    # 2. REQUEST VALIDATION
    # =====================================================

    if not pipeline_validate_request(
        body
    ):

        audit(
            request_id,
            "PIPELINE_INVALID_REQUEST",
            body
        )


        return JSONResponse(
            status_code=409,
            content={
                "error":
                    "INVALID_REQUEST"
            }
        )


    session = body[
        "session"
    ]

    revision = body[
        "revision"
    ]

    inputs = body[
        "inputs"
    ]

    events = body[
        "events"
    ]


    audit(
        request_id,
        "PIPELINE_REQUEST_PARSED",
        {
            "session":
                session,

            "revision":
                revision,

            "inputs":
                inputs,

            "eventCount":
                len(
                    events
                ),
        }
    )


    # =====================================================
    # 3. PREPARE A WORKING COPY
    #
    # Nothing is committed until the whole batch succeeds.
    # =====================================================

    existing_state = (
        PIPELINE_SESSIONS.get(
            session
        )
    )


    # -----------------------------------------------------
    # New session
    # -----------------------------------------------------

    if existing_state is None:

        working_state = (
            pipeline_new_session_state(
                revision,
                inputs
            )
        )


    # -----------------------------------------------------
    # Existing session
    # -----------------------------------------------------

    else:

        working_state = copy.deepcopy(
            existing_state
        )


        current_revision = (
            working_state[
                "revision"
            ]
        )


        # =================================================
        # Same revision
        # =================================================

        if revision == current_revision:


            supplied_fingerprint = (
                pipeline_inputs_fingerprint(
                    inputs
                )
            )


            # Same revision + ANY different input,
            # including extra metadata.
            if (
                supplied_fingerprint
                != working_state[
                    "inputsFingerprint"
                ]
            ):

                audit(
                    request_id,
                    "PIPELINE_REVISION_CONFLICT",
                    {
                        "session":
                            session,

                        "revision":
                            revision,
                    }
                )


                return JSONResponse(
                    status_code=409,
                    content={
                        "error":
                            "REVISION_CONFLICT"
                    }
                )


        # =================================================
        # Newer revision
        # =================================================

        elif revision > current_revision:


            # Replace inputs.
            working_state[
                "revision"
            ] = revision


            working_state[
                "inputs"
            ] = copy.deepcopy(
                inputs
            )


            working_state[
                "inputsFingerprint"
            ] = (
                pipeline_inputs_fingerprint(
                    inputs
                )
            )


            # IMPORTANT:
            # Clear current attempt / terminal state.
            working_state[
                "nodeStates"
            ] = {}


            # Cache stays.
            # Event ledger stays.


            audit(
                request_id,
                "PIPELINE_NEW_REVISION",
                {
                    "oldRevision":
                        current_revision,

                    "newRevision":
                        revision,
                }
            )


        # =================================================
        # Older request revision
        #
        # The controller must never roll state backward.
        
        # Treat the request as stale readback:
        # - keep the current revision
        # - keep the current inputs
        # - keep cache/state unchanged
        # - well-formed stale events are ignored
        # =================================================

        else:

            ignored_event_ids = []

            for event in events:

                if not pipeline_event_shape_valid(
                    event
                 ):

                    audit(
                        request_id,
                        "PIPELINE_STALE_INVALID_EVENT",
                        {
                            "suppliedRevision":
                                revision,

                            "currentRevision":
                                current_revision,
                            }
                    )

                    return JSONResponse(
                        status_code=409,
                        content={
                            "error":
                                "REVISION_CONFLICT"
                }
            )

                # Stale events do NOT consume their IDs.
                ignored_event_ids.append(
                    event[
                    "eventId"
                    ]
                    )

        nodes = pipeline_build_nodes(
            working_state
            )

        response = {

        # IMPORTANT:
        # Return the durable/current revision,
        # not the stale supplied revision.
            "revision":
                current_revision,

            "acceptedEventIds":
                [],

            "ignoredEventIds":
                ignored_event_ids,

            "nodes":
                nodes,
      }

        audit(
            request_id,
            "PIPELINE_STALE_READBACK",
        {
                "suppliedRevision":
                    revision,

                "currentRevision":
                    current_revision,

                "response":
                    response,
        }
    )


    return response


    # =====================================================
    # 4. PROCESS EVENT BATCH IN INPUT ORDER
    # =====================================================

    accepted_event_ids = []

    ignored_event_ids = []


    for (
        event_index,
        event
    ) in enumerate(
        events
    ):


        (
            outcome,
            conflict_code
        ) = pipeline_process_event(
            working_state,
            event
        )


        audit(
            request_id,
            "PIPELINE_EVENT_RESULT",
            {
                "index":
                    event_index,

                "eventId":
                    (
                        event.get(
                            "eventId"
                        )
                        if isinstance(
                            event,
                            dict
                        )
                        else None
                    ),

                "outcome":
                    outcome,

                "conflictCode":
                    conflict_code,
            }
        )


        # -------------------------------------------------
        # Accepted
        # -------------------------------------------------

        if outcome == "accept":

            accepted_event_ids.append(
                event[
                    "eventId"
                ]
            )


        # -------------------------------------------------
        # Ignored
        # -------------------------------------------------

        elif outcome == "ignore":

            # Shape is known valid for semantic ignores
            # and exact replay.
            ignored_event_ids.append(
                event[
                    "eventId"
                ]
            )


        # -------------------------------------------------
        # Conflict
        #
        # ROLLBACK ENTIRE REQUEST.
        #
        # working_state has not yet been committed.
        # -------------------------------------------------

        else:

            audit(
                request_id,
                "PIPELINE_BATCH_ROLLBACK",
                {
                    "error":
                        conflict_code,

                    "acceptedBeforeRollback":
                        accepted_event_ids,

                    "ignoredBeforeRollback":
                        ignored_event_ids,
                }
            )


            return JSONResponse(
                status_code=409,
                content={
                    "error":
                        conflict_code
                }
            )


    # =====================================================
    # 5. BUILD FINAL DAG VIEW
    # =====================================================

    nodes = pipeline_build_nodes(
        working_state
    )


    # =====================================================
    # 6. COMMIT STATE
    #
    # Only now does the batch become durable.
    # =====================================================

    PIPELINE_SESSIONS[
        session
    ] = working_state


    # =====================================================
    # 7. EXACT RESPONSE SHAPE
    # =====================================================

    response = {

        "revision":
            revision,

        "acceptedEventIds":
            accepted_event_ids,

        "ignoredEventIds":
            ignored_event_ids,

        "nodes":
            nodes,
    }


    # =====================================================
    # AUDIT
    # =====================================================

    audit(
        request_id,
        "PIPELINE_FINAL_RESPONSE",
        {
            "session":
                session,

            "response":
                response,
        }
    )


    return response
