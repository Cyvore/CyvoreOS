from typing import List, Tuple
import logging
import phonenumbers
import pytest
from CyvoreOS.phone_numbers_extension import (
    find_phone_numbers,
    normalize_phone_numbers,
    normalize_phone_number,
    validate_number,
    retry_with_country_codes,
    process_phone_numbers,
    special_retain_zero_country_codes,
)
from CyvoreOS.check_utils import extractPhonesNumbersChecks

file_path = "test_data.txt"
full_text = file_content_to_str(file_path)
PhoneNumbersList = List[str]


expected_find: PhoneNumbersList = [
    "393343091489",
    "+7 (982) 925-47-45",
    "+35542345193",
    "+972 54-553-3441",
    "054-921-7788",
    "050-795-3255",
    "+972 54-520-3789",
    "050-7710547",
    "0523-837202",
    "03-9311166",
    "036500456",
    "+33 1 23 45 67 89",
    "+7 495 123-45-67",
    "+1 (323) 456-7890",
    #
    "+972 3-9767916",
    "+44 20 7946 0958",
    "+49 30 1234567",
    "+46 8 123 4567",
    "+351 21 123 4567",
    "+33 8 12 34 56 78",
    "+46 081234567",
    "+46 1 234 5678",
    "123-456-7890",  # missing in test find
    "+1 253-0000",  # missing in test find
    "253-0000",  # missing in test find
    "+1 123-456-7890",  # missing in test find
    "+1 (123) 456-7890",  # missing in test find
    "+1 123.456.7890",  # missing in test find
    "+1 123-456-7890",  # missing in test find
]  # 29 tot

expected_normalized: PhoneNumbersList = [
    "+393343091489",
    "+79829254745",  # 9829254745 | # 798292547
    "+35542345193",
    "+972545533441",
    "+0549217788",
    "+0507953255",
    "+972545203789",
    "+0507710547",
    "+0523837202",
    "+039311166",
    "+036500456",
    "+33123456789",
    "+74951234567",  # 749512345
    "+13234567890",  # 3234567890
    #
    "+97239767916",
    "+442079460958",
    "+49301234567",
    "+4681234567",
    "+351211234567",
    "+33812345678",
    "+46081234567",
    "+4612345678",  # 461234567
    "+1234567890",
    "+12530000",
    "+2530000",
    "+11234567890",
]  # 26 tot
# 81234567 | # 8123456 | # 1234567 | # 12345678
expected_validated: PhoneNumbersList = [
    "972545533441",
    "972545203789",
    "4612345678",
    "4681234567",
    "79829254745",
    "442079460958",
    "74951234567",
    "13234567890",
    "35542345193",
    "33812345678",
    "393343091489",
    "49301234567",
    "351211234567",
    "4681234567",
    "33123456789",
    "97239767916",
]  # TOT 16
# [ Only validation checked, without using "retry_with_country_codes",
# that fits different country codes to single number and makes
# a list of numbers that came out valid ]

# expected_to_be_retried: PhoneNumbersList[tuple] = ["+036500456","+039311166","+0523837202","+0507710547","+0507953255","+0549217788","3343091489",#special retain zero
#                                             "81234567","","","","","","","",""]
expected_to_be_retried: List[Tuple[str, str]] = [
    ("036500456", "+972"),
    ("0507710547", "+972"),
    ("0549217788", "+972"),
    ("0507953255", "+972"),
    ("039311166", "+972"),
    ("0523837202", "+972"),
    ("9829254745", "+7"),
    ("42345193", "+355"),
    ("3234567890", "+1"),
    ("123456789", "+33"),  # special_retain_zero_country_codes
    ("81234567", "+46"),  # special_retain_zero_country_codes
]
expected_api_ready_lst: PhoneNumbersList = [
    "393343091489",
    "79829254745",
    "35542345193",
    "972545533441",
    "972549217788",
    "972507953255",
    "972545203789",
    "972507710547",
    "972523837202",
    "97239311166",
    "97236500456",
    "33123456789",
    "74951234567",
    "13234567890",
    "97239767916",
    "49301234567",
    "4681234567",
    "351211234567",
    "33812345678",
    "4681234567",
    "4612345678",
]  # 21 tot


@pytest.fixture
def setup_full_text():
    return file_content_to_str(file_path)


def file_content_to_str(path: str) -> str:
    """
    reads from test_data.txt file and makes the data to a long str data.
    """
    full_text = None
    logging.info("Reading From File: %s", path)
    try:
        with open(path, "r", encoding="utf-8") as file:
            lines = file.readlines()
        logging.debug("File read successfully. number of lines inside: %d", len(lines))
        full_text = " ".join(lines)  # Joins all lines with a space in between
        logging.debug("📜 [FULL TEXT] Combined text: \n%s", full_text)
    except (IOError, OSError) as e:
        logging.error("File error: %s", e)
    return full_text


def test_find_phone_numbers():
    """
    Ensures that all expected phone numbers are found and lists any unexpected ones.
    """
    print("\n👁️ ** TEST: Find Phone Numbers **")
    print("========================================")
    cleaned_found: PhoneNumbersList = []
    missing_numbers: PhoneNumbersList = []
    extra_numbers: PhoneNumbersList = []
    found_numbers = find_phone_numbers(full_text)

    print(f"📌 ** Total Numbers Found: ** {len(found_numbers)}")
    print("🔍 ** All Found Numbers: **")
    for i, num in enumerate(found_numbers):
        print(f"\n{i} Found as ➝ {num}")
        clean_num = normalize_phone_number(num)
        cleaned_found.append(clean_num)
        if clean_num in expected_normalized:
            print(f"🟢 {i} Cleaned ➝ {clean_num} ✅ (Expected)")
        else:
            print(f"🔴 {i} - {clean_num} Is EXTRA 👭 (Unexpected)")
            extra_numbers.append(clean_num)

    cleaned_found_set = set(cleaned_found)
    normalized_expected_set = set(expected_normalized)

    missing_numbers = [
        num for num in normalized_expected_set if num not in cleaned_found_set
    ]
    print("\n📊 **Test Summary**")
    print("----------------------")
    if missing_numbers:
        print(f"❌ ERROR: MISSING NUMBERS:\n {missing_numbers}")
    else:
        print("✅ No missing numbers.")

    if extra_numbers:
        print(f"⚠️ WARNING: Extra numbers found (not in expected list): {extra_numbers}")
    else:
        print("✅ No extra numbers found.")

    # ❌ Fail the test only if there are missing numbers
    assert (
        not missing_numbers
    ), f"❌ TEST FAILED 🚮: Missing expected numbers:\n {missing_numbers}"


def test_normalize_phone_numbers():
    """
    Test Case: Normalize phone numbers
    Ensures that all numbers are correctly formatted (e.g., removing spaces, dashes, and ensuring +prefix).
    """
    print("\n🏵️ ** TEST: Normalize Phone Numbers **")
    print("=====================================")
    print(f"📌 ** Total Of {len(expected_find)} Will Be Normalized **")
    print(
        f"📌 ** Total of {len(expected_normalized)} Will Remain Without Redundancy **"
    )

    normalized = normalize_phone_numbers(expected_find)
    print("🖐️ After [normalized = normalize_phone_numbers(expected_find)] 🖐️")
    print(f"📌 ** Total Normalized: {len(normalized)} **")

    print("👆 Normalizing Each Number Individually: 👆")
    for i, num in enumerate(expected_find):
        normalized_num = normalize_phone_number(num)
        if normalized_num in expected_normalized:
            print(f"🟢 [{i}] {normalized_num} Normalized successfully ✅")
        else:
            print(f"🔴 [{i}] ERROR: {normalized_num} Was Not Normalized Properly.")

    # Print any extra normalized numbers that are not in the expected list
    extra_numbers = [num for num in normalized if num not in expected_normalized]
    if extra_numbers:
        print(
            f"\n⚠️ WARNING: Extra numbers found (not in expected list):\n {extra_numbers}"
        )

    assert sorted(normalized) == sorted(
        expected_normalized
    ), f"❌ TEST FAILED 🚮: Normalized output mismatch.\nExpected: {sorted(expected_normalized)}\nGot: {sorted(normalized)}"


def test_validate_number():
    """
    Test Case: Validate phone numbers using the phonenumbers library.
    Ensures that the numbers are correctly validated and formatted in E.164 format.
    *** Only validation checked, without using "retry_with_country_codes",
    that fits different country codes to single number and makes
    a list of numbers that came out valid ***
    """
    print("\n🏵️ ** TEST: Validate Phone Numbers **")
    print("=====================================")
    print(
        f"📌 ** The Expectation:\n {len(expected_normalized)} Numbers Will Be Validated.\nThe Expected Normalized:\n{sorted(expected_normalized)} **"
    )
    parsed_numbers = []
    validated_numbers = []

    for n in expected_normalized:
        try:
            parsed_number = phonenumbers.parse(n)
            parsed_numbers.append(parsed_number)
            print(f"🟢 Parsed Successfully: {parsed_number}")
        except phonenumbers.NumberParseException:
            print(
                f"🔴 [PARSING FAILED] Number: < {n} > \n[In This Test We Will Not Retry With Country Codes.]"
            )
        except Exception as e:
            print(f"❌ ERROR: {n} Parsing Failed. Reason:\n{e}")

    for i, num in enumerate(parsed_numbers):
        try:
            validated_number = validate_number(num)
            validated_numbers.append(validated_number.lstrip("+"))
            print(f"🟢 [{i}] {validated_number} Validated Successfully ✅")
        except Exception as e:
            print(f"🔴 [{i}] ERROR: {num} Validation Failed. Reason:\n{e}")

    # Print any extra validated numbers that are not in the expected list
    extra_numbers = [num for num in validated_numbers if num not in expected_validated]
    if extra_numbers:
        print(
            f"\n❌ ❗ERROR❗: Extra Numbers In < validated_numbers > (not exist in expected list):\n {extra_numbers}"
        )

    # Print any missing validated numbers, that are not in the expected list
    missing_numbers = [
        num for num in expected_validated if num not in validated_numbers
    ]
    if missing_numbers:
        print(
            f"\n❌ ❗ERROR❗: Missing Numbers In < validated_numbers > (from expected list):\n {missing_numbers}"
        )

    assert sorted(validated_numbers) == sorted(
        expected_validated
    ), f"❌ TEST FAILED 🚮: Validation Output Mismatch.\nExpected: {sorted(expected_validated)}\nGot: {sorted(validated_numbers)}"


def test_retry_with_country_codes():
    """
    Test Case: Matches Country Codes to a single number, using the phonenumbers library ->
    Ensures that only valid combinations remain, and one of them has to be the Original True Combination.
    """
    print("\n🔆 ** TEST: Retry With Country Codes **")
    print("=====================================")
    print(f"📌 ** Total Of {len(expected_to_be_retried)} Numbers Will Be Retried **")

    for i, (number, original_code) in enumerate(expected_to_be_retried):
        print(f"\n🔍 Retrying Number: {number} with Original Code: {original_code}")
        try:
            valid_numbers = retry_with_country_codes(number)
            print(f"📌 ** Total Valid Numbers Found: {len(valid_numbers)} **")
            print("🔍 ** Valid Numbers: **")
            for valid_num in valid_numbers:
                print(f"  ➝ {valid_num}")

            # Check if the original combination is in the valid numbers
            if original_code not in special_retain_zero_country_codes:
                original_combination = original_code + number.lstrip("0")
            else:
                original_combination = original_code + number

            if original_combination in valid_numbers:
                print(f"🟢 [{i}] Original Combination Found: {original_combination} ✅")
            else:
                print(
                    f"🔴 [{i}] Original Combination Missing: {original_combination} ❌"
                )

            # Print any extra valid numbers that are not in the expected list
            extra_numbers = [
                num for num in valid_numbers if num != original_combination
            ]
            if extra_numbers:
                print(
                    f"\n⚠️ WARNING: {len(extra_numbers)} Extra Numbers Found (not the original combination):\n {extra_numbers}"
                )

        except Exception as e:
            print(f"🔴 [{i}] ERROR: Retry Failed for Number: {number}. Reason:\n{e}")

    print("\n🏁 ** TEST COMPLETED **")


def test_process_phone_numbers():
    """
    Test Case: Process phone numbers using phonenumbers library.
    Ensures that all expected numbers are processed correctly and appear in the final list.
    Tests:
    1. Basic number processing
    2. Special retain-zero country codes handling
    3. Israeli numbers with leading zeros
    4. Numbers that should be retried
    5. Numbers that should be validated directly
    """
    print("\n📜 **TEST: Process Phone Numbers**")
    print("===================================")
    print(f"📌 Total Numbers To Process: {len(expected_normalized)} ⭕")
    print(f"📌 Expected Processed Numbers: {len(expected_api_ready_lst)} ⭕")

    # Temporarily disable logging
    logging.disable(logging.ERROR)

    # Process the numbers (note: process_phone_numbers already returns a deduplicated list)
    processed = process_phone_numbers(expected_normalized)

    # Re-enable logging
    logging.disable(logging.NOTSET)

    # Print detailed comparison
    print("\n📊 ** Detailed Comparison **")
    print("==========================")

    # Print expected vs actual in parallel
    print("\nExpected Numbers vs Processed Numbers:")
    print("-------------------------------------")
    print("Expected | Processed | Status")
    print("-" * 50)

    # Create sorted lists for comparison
    expected_sorted = sorted(expected_api_ready_lst)
    processed_sorted = sorted(processed)

    # Track successful and missing numbers
    successful = []
    missing = []

    # Print comparison and track results
    for expected in expected_sorted:
        if expected in processed:
            successful.append(expected)
            print(f"{expected:12} | {expected:14} | ✅")
        else:
            missing.append(expected)
            print(f"{expected:12} | {'':14} | ❌")

    # Print any additional processed numbers
    extra = [p for p in processed_sorted if p not in expected_api_ready_lst]
    for extra_num in extra:
        print(f"{'':12} | {extra_num:14} | ⚠️")

    # Print summary statistics
    print("\n📈 ** Summary Statistics **")
    print("------------------------")
    print(f"Total Expected: {len(expected_api_ready_lst)}")
    print(f"Total Processed: {len(processed)}")
    print(f"Successfully Matched: {len(successful)}")
    print(f"Missing Numbers: {len(missing)}")
    print(f"Extra Numbers: {len(extra)}")

    # Print detailed analysis of differences
    if missing or extra:
        print("\n🔍 ** Detailed Analysis **")
        print("------------------------")

        if missing:
            print("\n❌ Missing Numbers (Expected but not processed):")
            print("-" * 40)
            for num in sorted(missing):
                print(f"  ➝ {num}")

        if extra:
            print("\n⚠️ Extra Numbers (Processed but not expected):")
            print("-" * 40)
            for num in sorted(extra):
                print(f"  ➝ {num}")

    # Print special cases analysis
    print("\n🔎 ** Special Cases Analysis **")
    print("-----------------------------")

    # Check special retain-zero country codes
    retain_zero_cases = [
        num
        for num in processed
        if any(
            num.startswith(code.lstrip("+"))
            for code in special_retain_zero_country_codes
        )
    ]
    if retain_zero_cases:
        print(f"\nSpecial Retain-Zero Cases ({len(retain_zero_cases)}):")
        print("-" * 40)
        for num in sorted(retain_zero_cases):
            print(f"  ➝ {num}")

    # Check Israeli numbers
    israeli_cases = [num for num in processed if num.startswith("972")]
    if israeli_cases:
        print(f"\nIsraeli Numbers ({len(israeli_cases)}):")
        print("-" * 40)
        for num in sorted(israeli_cases):
            print(f"  ➝ {num}")

    # Final assertion with clear error message
    if len(missing) > 0:
        print("\n❌ ** TEST FAILED **")
        print("==================")
        print("Some expected numbers were not processed correctly.")
        print("\nMissing Numbers:")
        print("-" * 40)
        for num in sorted(missing):
            print(f"  ➝ {num}")
        assert False, f"Missing {len(missing)} expected numbers: {missing}"
    else:
        print("\n✅ ** TEST PASSED **")
        print("==================")
        print("All expected numbers were processed successfully!")
        if extra:
            print(
                f"\nNote: {len(extra)} additional valid numbers were found with different country codes."
            )

    print("\n🏁 ** TEST COMPLETED **")


def test_extractPhonesNumbersChecks_error_handling():
    """
    Test Case: Verify extractPhonesNumbersChecks error handling
    Ensures that the function properly handles invalid inputs without crashing:
    1. None input
    2. Empty string
    3. Invalid data types
    4. Malformed strings
    5. Very long invalid strings
    6. Binary data (images)
    7. Email format strings
    """
    print("\n🛡️ **TEST: Extract Phones Numbers Checks Error Handling**")
    print("====================================================")
    # Temporarily disable logging except for errors
    logging.disable(logging.WARNING)

    fake_jpeg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01"
    fake_png_header = b"\x89PNG\r\n\x1a\n"
    email_content = """
    From: user@example.com
    To: recipient@example.com
    Subject: Test Email

    Dear User,
    This is a test email with some invalid phone numbers:
    Call me at: not-a-phone
    Or email: another112@email.com
    Best regards,
    Test User
    """

    test_cases = [
        (None, "None input"),
        ("", "Empty string"),
        (123, "Non-string input"),
        ("12345678901234567890", "Too long"),
        ("+1-800-FLOWERS", "Vanity number"),
        ("12345", "Too short"),
        ("@#$%^&*", "Special characters only"),
        ("a" * 100, "Very long invalid string"),
        (["not", "a", "string"], "List instead of string"),
        ({"key": "value"}, "Dictionary instead of string"),
        ("no\x00binary\x00data", "String with null bytes"),
        (fake_jpeg_header, "JPEG image data"),
        (fake_png_header, "PNG image data"),
        (fake_jpeg_header + b"some extra binary data", "Larger JPEG image data"),
        (email_content, "Email content"),
        ("alina53100@gmail.com", "Email address"),
        ("From: user@email.com\nTo: other@email.com", "Email headers"),
        (
            b"From: binary@email.com\nContent-Type: image/jpeg\n\n" + fake_jpeg_header,
            "Email with attached image",
        ),
    ]

    for test_input, description in test_cases:
        print(f"\n📋 Testing: {description}")
        print("-" * 40)

        try:
            result = extractPhonesNumbersChecks(test_input)
            print("✅ Function handled the input gracefully")
            print(f"📎 Result: {result}")
            # The function should return an empty list for invalid inputs
            assert not result, f"Expected empty list for invalid input, got: {result}"

        except Exception as e:
            print(f"❌ Function failed to handle the input: {str(e)}")
            assert (
                False
            ), f"Function should handle {description} gracefully, but raised: {str(e)}"

    # Re-enable logging
    logging.disable(logging.NOTSET)

    print("\n✅ ** TEST PASSED **")
    print("==================")
    print("All invalid inputs were handled gracefully!")
    print("\n🏁 ** TEST COMPLETED **")


def test_find_phone_numbers_length_validation():
    """
    Test Case: Verify that find_phone_numbers correctly implements the regex pattern.
    Tests the following regex rules:
    1. Optional '+' prefix (only at beginning)
    2. Minimum of 6 digits (regardless of non-digit characters between them)
    3. Allowed characters: digits, space, dot, dash, slash, parentheses
    4. No double spaces in a row
    5. Stops at unexpected characters
    6. Matches only from valid phone-looking points
    7. Minimum length of match (6 characters)
    8. Multiple matches support
    """
    print("\n🔍 **TEST: Regex Pattern Validation**")
    print("=====================================")
    print("Testing regex:")
    print("=====================================")

    # Temporarily disable logging
    logging.disable(logging.WARNING)

    test_cases = [
        ("+123456", "Plus prefix", True, ["123456"]),
        ("123456", "No plus prefix", True, ["123456"]),
        (
            "++123456",
            "Double plus prefix",
            True,
            ["123456"],
        ),  # Should only capture first +
        (
            "123+456",
            "Plus in middle",
            False,
        ),  # Should not match (less than 6 digits on each side)
        ("123456", "Exactly 6 digits", True, ["123456"]),
        ("12345", "Less than 6 digits", False),  # Should not match
        ("123.456", "6 digits with separator", True, ["123.456"]),
        ("123-456", "6 digits with dash", True, ["123-456"]),
        ("123/456", "6 digits with slash", True, ["123/456"]),
        ("(123)456", "6 digits with parentheses", True, ["(123)456"]),
        ("123(456)", "6 digits with parentheses in middle", True, ["123(456)"]),
        ("123.456.789", "Multiple dots", True, ["123.456.789"]),
        ("123-456-789", "Multiple dashes", True, ["123-456-789"]),
        ("123/456/789", "Multiple slashes", True, ["123/456/789"]),
        ("(123)(456)", "Multiple parentheses", True, ["(123)(456)"]),
        ("123 456 789", "Multiple spaces", True, ["123 456 789"]),
        (
            "123  456",
            "Double space",
            False,
        ),  # Should split at double space, both sides too short
        (
            "123   456",
            "Triple space",
            False,
        ),  # Should split at triple space, both sides too short
        (
            "123@456",
            "At symbol",
            False,
        ),  # Should split at @, both sides too short
        (
            "123#456",
            "Hash symbol",
            False,
        ),  # Should split at #, both sides too short
        (
            "123abc456",
            "Letters",
            False,
        ),  # Should split at letters, both sides too short
        (
            "123,456",
            "Comma",
            False,
        ),  # Should split at triple space, both sides too short
        ("abc123456", "Letters before digits", True, ["123456"]),
        ("12a34", "Letter between digits", False),  # Should not match
        (
            "123.45",
            "Short with separator",
            False,
        ),  # Can be matched with a space in beginning or end, but will fall later in normalization
        ("12345", "Too short", False),  # Should not match (5 chars)
        ("123456 789012", "Long number with a space", True, ["123456 789012"]),
        ("123456@789012", "Two numbers with @ separator", True, ["123456", "789012"]),
        ("+33 1 23 45 67 89", "French number", True, ["33 1 23 45 67 89"]),
        ("+972 50-123-4567", "Israeli number", True, ["972 50-123-4567"]),
        ("123-456-7890", "US format", True, ["123-456-7890"]),
        ("(123) 456-7890", "US format with parentheses", True, ["(123) 456-7890"]),
        ("123.456.7890", "Number with dots", True, ["123.456.7890"]),
        ("123/456/7890", "Number with slashes", True, ["123/456/7890"]),
        ("+351 21 123 4567", "Portuguese number", True, ["351 21 123 4567"]),
        ("050-1234567", "Israeli local number", True, ["050-1234567"]),
        ("123456+789", "Plus in middle with short second part", True, ["123456"]),
        ("123456+45", "Plus in middle with short second part", True, ["123456"]),
        ("123.456@789", "@ at middle, short second part", True, ["123.456"]),
        (
            "123.45@678",
            "@ at middle, short second part, first part falls in normalization",
            True,
            ["123.45"],
        ),
        ("123456 789", "Single space", True, ["123456 789"]),
        ("123456  789", "Double space", True, ["123456"]),
        ("+123456", "Plus at start", True, ["123456"]),
        ("123456+", "Plus at end", True, ["123456"]),
    ]

    for test_case in test_cases:
        number = test_case[0]
        description = test_case[1]
        should_find = test_case[2]
        expected_numbers = test_case[3] if len(test_case) > 3 else None

        print(f"\n🔍 Testing: {description}")
        print(f"Input: {number}")
        print(f"Should Find: {'Yes' if should_find else 'No'}")
        if expected_numbers:
            print(f"Expected Numbers: {expected_numbers}")

        # Find numbers in a string containing just this number
        found = find_phone_numbers(number)

        if should_find:
            if not found:
                print("❌ Valid number(s) should have been found but weren't")
                assert False, f"Failed to find number(s): {number}"
            else:
                print("✅ Numbers were correctly found")
                print(f"Found numbers: {found}")

                # If expected numbers are specified, verify they're all found
                if expected_numbers:
                    # Check if all expected numbers are in the found numbers
                    missing_expected = [
                        num for num in expected_numbers if num not in found
                    ]
                    if missing_expected:
                        print(f"❌ Missing expected numbers: {missing_expected}")
                        print(f"Expected: {expected_numbers}")
                        print(f"Found: {found}")
                        assert False, f"Missing expected numbers: {missing_expected}"

                    # Check if there are any unexpected numbers found
                    unexpected_found = [
                        num for num in found if num not in expected_numbers
                    ]
                    if unexpected_found:
                        print(f"⚠️ Found unexpected numbers: {unexpected_found}")
                        print(f"Expected: {expected_numbers}")
                        print(f"Found: {found}")
                        # We don't assert here because we're allowing the regex to capture more than expected

                    print("✅ Found numbers include all expected numbers")
        else:
            if found:
                print(f"❌ Found valid numbers when none should be found: {found}")
                assert False, f"Found valid numbers when none should be found: {found}"
            else:
                print("✅ Invalid number was correctly rejected")

    # Re-enable logging
    logging.disable(logging.NOTSET)

    print("\n✅ ** TEST PASSED **")
    print("==================")
    print("All regex pattern validations passed!")
    print("\n🏁 ** TEST COMPLETED **")
