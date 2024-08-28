#!/usr/bin/env bash

# Function to verify directory existence and respective permissions
check_directory_permissions() {
    local dir="$1"
    local expected_perm="$2"

    echo "------------------------------------"
    echo "Checking directory: $dir"

    # Check if the directory exists
    if [ -d "$dir" ]; then
        echo "Directory $dir exists."

        # Check if permissions match
        existing_perm="$(stat -c '%a' "$dir")"
        if [ "$(stat -c '%a' "$dir")" = "$expected_perm" ]; then
            echo "Permissions are matched: $expected_perm"
        else
            echo "Permissions do not match. Expected: $expected_perm. Existing: $existing_perm"
            exit 1
        fi
    else
        echo "Directory $dir does not exist or is not a directory."
        exit 1
    fi

    echo "------------------------------------"
}

# Verifying the directories existence and respective permissions which are in /ericsson/tor/data mount.
# Add more directories and respective permissions as needed and add respective volumes and volumeMounts in Job(JobToCheckDirPermissions.yaml)
check_directory_permissions "/ericsson/tor/data/cm_events" "2775"
check_directory_permissions "/ericsson/tor/data/apps" "2775"
