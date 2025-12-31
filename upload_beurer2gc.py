#!/usr/bin/env python3
"""
From Simple Garmin Connect API Example
=======================================

This example demonstrates the basic usage of python-garminconnect:
- Authentication with email/password
- Token storage and automatic reuse
- MFA (Multi-Factor Authentication) support
- Comprehensive error handling for all API calls

Dependencies:
pip3 install garminconnect garth requests

Environment Variables (optional):
export EMAIL=<your garmin email address>
export PASSWORD=<your garmin password>
export GARMINTOKENS=<path to token storage>
"""

import logging
import os
import sys
from datetime import date
from getpass import getpass
from pathlib import Path

import requests
from garth.exc import GarthException, GarthHTTPError

from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

import csv
import hashlib
import json
from datetime import datetime, timedelta

max_age_days = 30

# Suppress garminconnect library logging to avoid tracebacks in normal operation
logging.getLogger("garminconnect").setLevel(logging.CRITICAL)


def safe_api_call(api_method, *args, **kwargs):
    """
    Safe API call wrapper with comprehensive error handling.

    This demonstrates the error handling patterns used throughout the library.
    Returns (success: bool, result: Any, error_message: str)
    """
    try:
        result = api_method(*args, **kwargs)
        return True, result, None

    except GarthHTTPError as e:
        # Handle specific HTTP errors gracefully
        error_str = str(e)
        status_code = getattr(getattr(e, "response", None), "status_code", None)

        if status_code == 400 or "400" in error_str:
            return (
                False,
                None,
                "Endpoint not available (400 Bad Request) - Feature may not be enabled for your account",
            )
        elif status_code == 401 or "401" in error_str:
            return (
                False,
                None,
                "Authentication required (401 Unauthorized) - Please re-authenticate",
            )
        elif status_code == 403 or "403" in error_str:
            return (
                False,
                None,
                "Access denied (403 Forbidden) - Account may not have permission",
            )
        elif status_code == 404 or "404" in error_str:
            return (
                False,
                None,
                "Endpoint not found (404) - Feature may have been moved or removed",
            )
        elif status_code == 429 or "429" in error_str:
            return (
                False,
                None,
                "Rate limit exceeded (429) - Please wait before making more requests",
            )
        elif status_code == 500 or "500" in error_str:
            return (
                False,
                None,
                "Server error (500) - Garmin's servers are experiencing issues",
            )
        elif status_code == 503 or "503" in error_str:
            return (
                False,
                None,
                "Service unavailable (503) - Garmin's servers are temporarily unavailable",
            )
        else:
            return False, None, f"HTTP error: {e}"

    except FileNotFoundError:
        return (
            False,
            None,
            "No valid tokens found. Please login with your email/password to create new tokens.",
        )

    except GarminConnectAuthenticationError as e:
        return False, None, f"Authentication issue: {e}"

    except GarminConnectConnectionError as e:
        return False, None, f"Connection issue: {e}"

    except GarminConnectTooManyRequestsError as e:
        return False, None, f"Rate limit exceeded: {e}"

    except Exception as e:
        return False, None, f"Unexpected error: {e}"


def get_credentials():
    """Get email and password from environment or user input."""
    email = os.getenv("EMAIL")
    password = os.getenv("PASSWORD")

    if not email:
        email = input("Login email: ")
    if not password:
        password = getpass("Enter password: ")

    return email, password


def init_api() -> Garmin | None:
    """Initialize Garmin API with authentication and token management."""

    # Configure token storage
    tokenstore = os.getenv("GARMINTOKENS", "~/.garminconnect")
    tokenstore_path = Path(tokenstore).expanduser()

    print(f"Token storage: {tokenstore_path}")

    # Check if token files exist
    if tokenstore_path.exists():
        print("Found existing token directory")
        token_files = list(tokenstore_path.glob("*.json"))
        if token_files:
            print(
                f"Found {len(token_files)} token file(s): {[f.name for f in token_files]}"
            )
        else:
            print("Token directory exists but no token files found")
    else:
        print("No existing token directory found")

    # First try to login with stored tokens
    try:
        print("Attempting to use saved authentication tokens...")
        garmin = Garmin()
        garmin.login(str(tokenstore_path))
        print("Successfully logged in using saved tokens!")
        return garmin

    except (
        FileNotFoundError,
        GarthHTTPError,
        GarminConnectAuthenticationError,
        GarminConnectConnectionError,
    ):
        print("No valid tokens found. Requesting fresh login credentials.")

    # Loop for credential entry with retry on auth failure
    while True:
        try:
            # Get credentials
            email, password = get_credentials()

            print("Logging in with credentials...")
            garmin = Garmin(
                email=email, password=password, is_cn=False, return_on_mfa=True
            )
            result1, result2 = garmin.login()

            if result1 == "needs_mfa":
                print("Multi-factor authentication required")

                mfa_code = input("Please enter your MFA code: ")
                print("Submitting MFA code...")

                try:
                    garmin.resume_login(result2, mfa_code)
                    print("MFA authentication successful!")

                except GarthHTTPError as garth_error:
                    # Handle specific HTTP errors from MFA
                    error_str = str(garth_error)
                    if "429" in error_str and "Too Many Requests" in error_str:
                        print("Too many MFA attempts")
                        print("Please wait 30 minutes before trying again")
                        sys.exit(1)
                    elif "401" in error_str or "403" in error_str:
                        print("Invalid MFA code")
                        print("Please verify your MFA code and try again")
                        continue
                    else:
                        # Other HTTP errors - don't retry
                        print(f"MFA authentication failed: {garth_error}")
                        sys.exit(1)

                except GarthException as garth_error:
                    print(f"MFA authentication failed: {garth_error}")
                    print("Please verify your MFA code and try again")
                    continue

            # Save tokens for future use
            garmin.garth.dump(str(tokenstore_path))
            print(f"Authentication tokens saved to: {tokenstore_path}")
            print("Login successful!")
            return garmin

        except GarminConnectAuthenticationError:
            print("Authentication failed:")
            print("Please check your username and password and try again")
            # Continue the loop to retry
            continue

        except (
            FileNotFoundError,
            GarthHTTPError,
            GarminConnectConnectionError,
            requests.exceptions.HTTPError,
        ) as err:
            print(f"Connection error: {err}")
            print("Please check your internet connection and try again")
            return None

        except KeyboardInterrupt:
            print("\nCancelled by user")
            return None



"""
 Support functions
 =================
"""
def parse_datetime(date_str, time_str) -> str:
    # Convert date from 'DD.MM.YYYY' to 'YYYY-MM-DD'
    #
    iso_timestamp = date_str.strip() + "T" + time_str.strip()
    try:
        return datetime.strptime(iso_timestamp, "%d.%m.%YT%H:%M").isoformat()
    except ValueError:
        return iso_timestamp



def get_hash(measurement: dict) -> str:
    # Calculate hash of measurements dict
    #
    return hashlib.sha256(json.dumps(measurement, sort_keys=True, default=str).encode('utf-8')).hexdigest()



def get_gc_weight_hashes(api: Garmin, dayspan=max_age_days) -> [str]:
    # Get weight measurements from Garmin Connect and return hashes
    #
    date_end = datetime.today().strftime('%Y-%m-%d')
    date_start = (datetime.today() - timedelta(days=dayspan)).strftime('%Y-%m-%d')

    success, gc_measurements, error_msg = safe_api_call(
                      api.get_weigh_ins,
                      date_start,
                      date_end
                      )
    if not success:
       print(f"Error getting weight values from garmin connect: {error_msg}")

    hashes = []

    for summary in gc_measurements['dailyWeightSummaries']:
        for measurement in summary['allWeightMetrics']:
            # make sure to use same data format as in local csv file
            #
            m = dict()
            m['weight'] = round(measurement['weight'] / 1000, 1)
            m['timestamp'] = datetime.fromtimestamp( measurement['timestampGMT'] / 1000 ).isoformat()

            hashes.append( get_hash(m) )

    return hashes



def get_gc_bloodp_hashes(api: Garmin, dayspan=max_age_days) -> [str]:
    # Get blood pressure measurements from Garmin Connect and return hashes
    #
    date_end = datetime.today().strftime('%Y-%m-%d')
    date_start = (datetime.today() - timedelta(days=dayspan)).strftime('%Y-%m-%d')

    success, gc_measurements, error_msg = safe_api_call(
                      api.get_blood_pressure,
                      date_start,
                      date_end
                      )
    if not success:
       print(f"Error getting blood pressure values from garmin connect: {error_msg}")

    hashes = []

    # Extract measurements from garmin structure
    for measurement_summary in gc_measurements['measurementSummaries']:
        for measurement in measurement_summary['measurements']:
            m = dict()

            m['sys'] = measurement['systolic']
            m['dia'] = measurement['diastolic']
            m['pulse'] = measurement['pulse']

            m['timestamp'] = datetime.fromisoformat(measurement['measurementTimestampLocal']).isoformat()

            hashes.append( get_hash(m) )

    return hashes



def parse_and_upload(input_filename, api: Garmin):

    if not os.path.isfile(input_filename):
        print(f"Input file not found: {input_filename}")
        sys.exit(1)

    with open(input_filename, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Locate sections and column names
    #
    weight_header = None
    weight_end = None

    bloodp_header = None
    bloodp_end = None

    for i, line in enumerate(lines):
        if line.startswith("Gewicht"):
           weight_header = i + 1

        elif line.startswith("Blutdruck"):
           bloodp_header = i + 1

        elif line in ['\n', '\r\n']:
           if weight_header is not None and weight_end is None:
              weight_end = i - 1
           elif bloodp_header is not None and bloodp_end is None:
              bloodp_end = i - 1

    # Read weight measurements from local csv file
    #
    csv_content = lines[weight_header:weight_end]
    reader = csv.DictReader(csv_content, delimiter=";")

    readings_weight = []

    for row in reader:
        date_orig = row.get("Datum", "").strip()
        time_orig = row.get("Uhrzeit", "").strip()
        weight = "0" + row.get("kg", "").strip().replace(",", ".")
        bmi = "0" + row.get("BMI", "").strip().replace(",", ".")
        percent_fat = "0" + row.get("Körperfett", "").strip().replace(",", ".")
        percent_water = "0" + row.get("Wasser", "").strip().replace(",", ".")
        muscles = "0" + row.get("Muskeln", "").strip().replace(",", ".")
        bone_mass = "0" + row.get("Knochen", "").strip().replace(",", ".")
        visceral_fat = "0" + row.get("Viszeralfett", "").strip().replace(",", ".")
        metabolic_age = "0" + row.get("Metabolisches Alter").strip().replace(",", ".")

        if date_orig and time_orig and weight and bmi:
            timestamp = parse_datetime(date_orig, time_orig)
            readings_weight.append(
                (
                    timestamp,
                    float(weight),
                    float(bmi),
                    float(percent_fat),
                    float(percent_water),
                    float(muscles) * float(weight) / 100.0,
                    float(bone_mass),
                    float(visceral_fat),
                    float(metabolic_age)
                )
            )

    # Get Garmin Connect measurement hashes to avoid upload of already existing entries
    #
    gc_hashes = get_gc_weight_hashes(api)

    for (
        timestamp,
        weight,
        bmi,
        percent_fat,
        percent_water,
        muscle_mass,
        bone_mass,
        visceral_fat,
        metabolic_age
        ) in readings_weight:
             m = dict()
             m['weight'] = weight
             m['timestamp'] = timestamp

             print(f"{timestamp}: {weight} kg, {bmi} ...")

             if get_hash(m) not in gc_hashes:
                print("Uploading")
                safe_api_call(
                    api.add_body_composition,
                    timestamp,
                    weight=weight,
                    bmi=bmi,
                    percent_fat=percent_fat,
                    percent_hydration=percent_water,
                    visceral_fat_rating=visceral_fat,
                    bone_mass=bone_mass,
                    muscle_mass=muscle_mass,
                    metabolic_age=metabolic_age
                )
             else:
                print("Duplicate entry found on Garmin Connect - not uploading")


    # Read blood pressure measurements from local csv file
    #
    csv_content = lines[bloodp_header:bloodp_end]
    reader = csv.DictReader(csv_content, delimiter=";")

    readings_bloodp = []
    for row in reader:
        date_orig = row.get("Datum", "").strip()
        time_orig = row.get("Uhrzeit", "").strip()
        sys = "0" + row.get("Sys", "").strip().replace(",", ".")
        dia = "0" + row.get("Dia", "").strip().replace(",", ".")
        pulse = "0" + row.get("Puls", "").strip().replace(",", ".")

        if date_orig and time_orig and sys and dia:
            timestamp = parse_datetime(date_orig, time_orig)
            readings_bloodp.append(
                (
                    timestamp,
                    int(sys),
                    int(dia),
                    int(pulse)
                )
            )

    # Get Garmin Connect measurement hashes to avoid upload of already existing entries
    #
    gc_hashes = get_gc_bloodp_hashes(api)

    for (
        timestamp,
        sys,
        dia,
        pulse
        ) in readings_bloodp:
             m = dict()

             m['sys'] = sys
             m['dia'] = dia
             m['pulse'] = pulse
             m['timestamp'] = timestamp

             print(f"{timestamp}: {sys}/{dia} mmHg, {pulse}")

             if get_hash(m) not in gc_hashes:
                print("Uploading")
                safe_api_call(
                    api.set_blood_pressure,
                    sys,
                    dia,
                    pulse,
                    timestamp
                )
             else:
                print("Duplicate entry found on Garmin Connect - not uploading")



def display_user_info(api: Garmin):
    """Display basic user information with proper error handling."""
    print("\n" + "=" * 60)
    print("User Information")
    print("=" * 60)

    # Get user's full name
    success, full_name, error_msg = safe_api_call(api.get_full_name)
    if success:
        print(f"Name: {full_name}")
    else:
        print(f"Name: {error_msg}")

    # Get user profile number from device info
    success, device_info, error_msg = safe_api_call(api.get_device_last_used)
    if success and device_info and device_info.get("userProfileNumber"):
        user_profile_number = device_info.get("userProfileNumber")
        print(f"Profile Number: {user_profile_number}")
    else:
        if not success:
            print(f"Profile Number: {error_msg}")
        else:
            print("Profile Number: Not available")



def main():
    """Main using  Garmin Connect API."""

    # Initialize API with authentication (will only prompt for credentials if needed)
    api = init_api()

    if not api:
        print("Failed to initialize API. Exiting.")
        return

    # Display user information
    display_user_info(api)


    if len(sys.argv) == 2:
        input_file = sys.argv[1]
    else:
        print("No file given - usage: <scriptname> <csv file>")
        exit(1)

    parse_and_upload(input_file, api)

    print("\n" + "=" * 60)
    print("Completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting example. Goodbye!")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
