import logging
from typing import List
import re
import copy
import phonenumbers
from .regex_patterns import USPHONEREG, ISPHONEREG, EUPHONEREG

PhoneNumbersList = List[str]


special_retain_zero_country_codes: List[str] = [
    "+39",
    "+33",
    "+46",
]  # Italy, France, Sweden.

country_codes: List[str] = [
    "+972",  # Israel: 054-123-4567 -> +972 54-123-4567
    "+1",  # United States/Canada: (202) 555-0198 -> +1 (202) 555-0198
    "+355",  # Albania: 042 345 678 -> +355 42 345 678
    "+376",  # Andorra: 345 678 -> +376 345 678
    "+374",  # Armenia: (10) 123-456 -> +374 10 123-456
    "+43",  # Austria: 01 234 5678 -> +43 1 234 5678
    "+994",  # Azerbaijan: (12) 345-6789 -> +994 12 345-6789
    "+375",  # Belarus: 29 123-45-67 -> +375 29 123-45-67
    "+32",  # Belgium: (2) 456 78 90 -> +32 2 456 78 90
    "+387",  # Bosnia and Herzegovina: 33 123 456 -> +387 33 123 456
    "+359",  # Bulgaria: (2) 123-4567 -> +359 2 123-4567
    "+385",  # Croatia: 01 234 5678 -> +385 1 234 5678
    "+357",  # Cyprus: 22 123 456 -> +357 22 123 456
    "+420",  # Czech Republic: 123 456 789 -> +420 123 456 789
    "+45",  # Denmark: 12 34 56 78 -> +45 12 34 56 78
    "+372",  # Estonia: 5123 4567 -> +372 5123 4567
    "+298",  # Faroe Islands: 212345 -> +298 212345
    "+358",  # Finland: 9 123 4567 -> +358 9 123 4567
    "+33",  # France: 01 09 75 83 51 -> +33 1 09 75 83 51
    "+995",  # Georgia: 32 123 4567 -> +995 32 123 4567
    "+49",  # Germany: (30) 1234-5678 -> +49 30 1234-5678
    "+350",  # Gibraltar: 200 12345 -> +350 200 12345
    "+30",  # Greece: 21 1234 5678 -> +30 21 1234 5678
    "+299",  # Greenland: 321234 -> +299 321234
    "+36",  # Hungary: 1 234 5678 -> +36 1 234 5678
    "+354",  # Iceland: 123 4567 -> +354 123 4567
    "+353",  # Ireland: (01) 234 5678 -> +353 1 234 5678
    "+39",  # Italy: 06 6989 1234 -> +39 06 6989 1234
    "+383",  # Kosovo: 38 123 456 -> +383 38 123 456
    "+371",  # Latvia: 67 123 456 -> +371 67 123 456
    "+423",  # Liechtenstein: 234 5678 -> +423 234 5678
    "+370",  # Lithuania: (8-5) 123 4567 -> +370 8-5 123 4567
    "+352",  # Luxembourg: 621 123 456 -> +352 621 123 456
    "+356",  # Malta: 21 234 567 -> +356 21 234 567
    "+373",  # Moldova: 22 123 456 -> +373 22 123 456
    "+377",  # Monaco: 93 15 67 89 -> +377 93 15 67 89
    "+382",  # Montenegro: 20 123 456 -> +382 20 123 456
    "+31",  # Netherlands: 20 123 4567 -> +31 20 123 4567
    "+389",  # North Macedonia: 2 123 456 -> +389 2 123 456
    "+47",  # Norway: 123 45 678 -> +47 123 45 678
    "+48",  # Poland: 22 123 45 67 -> +48 22 123 45 67
    "+351",  # Portugal: 21 234 5678 -> +351 21 234 5678
    "+40",  # Romania: 21 234 5678 -> +40 21 234 5678
    "+7",  # Russia: (495) 123-45-67 -> +7 495 123-45-67
    "+378",  # San Marino: 0549 123 456 -> +378 549 123 456
    "+381",  # Serbia: 11 123 4567 -> +381 11 123 4567
    "+421",  # Slovakia: 2/123 45 67 -> +421 2/123 45 67
    "+386",  # Slovenia: 31 123 456 -> +386 31 123 456
    "+34",  # Spain: 912 345 678 -> +34 912 345 678
    "+46",  # Sweden: (08) 123 4567 -> +46 8 123 4567
    "+41",  # Switzerland: (0)22 123 45 67 -> +41 22 123 45 67
    "+90",  # Turkey: (212) 123 4567 -> +90 212 123 4567
    "+380",  # Ukraine: 44 123 4567 -> +380 44 123 4567
    "+44",  # United Kingdom: (20) 7946 0958 -> +44 20 7946 0958
    "+39",  # Vatican City: 06 6989 -> +39 06 6989
]


def find_phone_numbers(data: str) -> List[str]:
    """
    Finds Phone Numbers If Exist In Data
    """
    rgx_possible = set()
    logging.info("Looking For Phone Numbers")
    matches_us = re.findall(USPHONEREG, data)
    matches_israel = re.findall(ISPHONEREG, data)
    matches_europe = re.findall(EUPHONEREG, data)
    all_matches = matches_us + matches_israel + matches_europe
    logging.debug(
        "Regex matches - US: %d, Israel: %d, Europe: %d",
        len(matches_us),
        len(matches_israel),
        len(matches_europe),
    )
    for match in all_matches:
        rgx_possible.add((match.strip()).lstrip("+"))
    return list(rgx_possible)


def normalize_phone_number(phone: str) -> str:
    """
    Normalizes a phone number by removing non-numeric symbols (except '+')
    and ensuring it starts with a '+' if not already present.
            (phonenumbers lib checks numbers better with + at start)
    """
    # Remove all characters except digits and '+'
    normalized = re.sub(r"[^\d\+]", "", phone)
    logging.debug("After removing non-numeric symbols: %s", normalized)

    # Ensure the phone number starts with '+'
    if not normalized.startswith("+"):
        normalized = "+" + normalized

    logging.info("Final normalized phone number: %s", normalized)
    return normalized


def normalize_phone_numbers(phone_list: PhoneNumbersList) -> PhoneNumbersList:
    """
    Normalizes a list of phone numbers, ensuring each number starts with '+'
    and contains only valid characters for phone numbers.
    """
    logging.info(
        "Starting normalization of phone numbers. Total numbers: %d", len(phone_list)
    )
    normal = set()
    for phone in phone_list:
        logging.debug("Normalizing number: %s", phone)
        normalized_phone = normalize_phone_number(phone)
        normal.add(normalized_phone)
    normalized_list = list(normal)
    logging.info("NORMALIZATION COMPLETE.")
    return normalized_list


def validate_number(n: phonenumbers.PhoneNumber) -> str:
    """
    Validates a PhoneNumber object from the phonenumbers library.
    Checks if the number is possible and valid. Returns the formatted number in E.164 format if valid.
    """
    num = copy.deepcopy(n)  # coppied phonenumbers object
    try:
        e164_number = phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.E164
        )
        logging.debug("\n                   After formatting: %s", e164_number)
        logging.debug("                     STARTING VALIDATION")
    except Exception as e:
        logging.warning("Error formatting number: %s", e)

    if phonenumbers.is_possible_number(num):
        logging.debug("The number %s is a possible number.", num)
        if phonenumbers.is_valid_number(num):
            logging.info("%s | $ NUMBER IS VALID $", num)
            return e164_number
        else:
            raise Exception("The number is possible but not valid.")
    else:
        raise Exception("The number is not possible.")


def retry_with_country_codes(phone_number: str) -> List[str]:
    """Function will return a list of the same number with different country codes that validate successfully.
    Special handling is applied for countries that retain leading zeros in phone numbers.
    """
    logging.info(
        "                    Starting retry with country codes for number: %s",
        phone_number,
    )
    valid_numbers = []
    stripped_from_plus = phone_number.lstrip("+")

    for code in country_codes:
        try:
            if code not in special_retain_zero_country_codes:
                full_number = code + stripped_from_plus.lstrip("0")
                logging.debug(
                    "\n                   Trying with country code %s: %s",
                    code,
                    full_number,
                )
            else:
                full_number = code + stripped_from_plus  # keep '0'
                logging.debug(
                    "< special_retain_zero > Trying country code %s with leading '0' for number: %s",
                    code,
                    full_number,
                )  # ["+39", "+33", "+46"]
            parsed_number = phonenumbers.parse(full_number)
            result = validate_number(parsed_number)

            if result not in valid_numbers:
                logging.info(
                    "Successfully validated number with country code %s: %s",
                    code,
                    result,
                )
                valid_numbers.append(result)

        except phonenumbers.NumberParseException:
            logging.warning(
                "Failed to parse number with country code %s: %s", code, phone_number
            )
        except Exception as error:
            logging.error(
                "Validation Problem for number: < %s > | %s", parsed_number, error
            )
    if valid_numbers:
        logging.info(
            "Retry successful. Total valid numbers found: %d", len(valid_numbers)
        )
    else:
        raise Exception("Retry failed with all country codes.")
    return valid_numbers


def process_phone_numbers(
    normalized: List[str],
) -> List[str]:
    """Main function to parse and validate phone numbers."""
    logging.info(
        "Starting phone number processing. Total normalized numbers to process: %d",
        len(normalized),
    )
    results = set()

    for num in normalized:
        result = None
        try:
            parsed = phonenumbers.parse(
                num
            )  # parsed = phonenumbers.parse("+442083661177") ==> Country Code: 44 National Number: 2083661177 Leading Zero: False
            # after parse -> PhoneNumber object
            res = validate_number(parsed)
            result = res.lstrip("+")

            logging.info("Number parsed and validated successfully: %s", res)
            results.add(result)
        except phonenumbers.NumberParseException:
            logging.warning(
                "Parsing failed for number: %s. Retrying with country codes.", num
            )
        except Exception as error:
            logging.error("Validation failed for number: < %s > | %s", num, error)

        if result and result not in results:
            try:
                retried_list = retry_with_country_codes(num)
                if retried_list:
                    for ret in retried_list:
                        logging.info(
                            "Retry successful for number: %s. Validated as: %s",
                            num,
                            ret,
                        )
                        results.add(ret.lstrip("+"))
            except Exception as error:
                logging.error("For number:    %s      %s", num, error)
    logging.info("Finished processing. Total valid numbers found: %d", len(results))
    return list(results)
