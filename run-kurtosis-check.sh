#!/bin/bash
set -euo pipefail
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# ------------------------------------------------
#          Inputs on how to run checks
# ------------------------------------------------
echo
printf "Do you want to run the checks in terminal or visit the assertoor URL? (terminal/url) "
read reply

echo
printf "Build new changes (yes/no)? "
read use_previous_image

# ------------------------------------------------
#             Installation Checks
# ------------------------------------------------

# Checking for docker installation
echo "Checking docker installation"
if command -v docker &> /dev/null; then
  echo "Docker installation found"
else
  echo "Docker installation not found. Please install docker."
  exit 1
fi

echo "Checking kurtosis installation"
if command -v kurtosis &> /dev/null; then
  echo "Kurtosis installation found"
else
  echo "Kurtosis installation not found. Installing kurtosis"
  echo "deb [trusted=yes] https://apt.fury.io/kurtosis-tech/ /" | sudo tee /etc/apt/sources.list.d/kurtosis.list
  sudo apt-get update
  sudo apt-get install -y kurtosis
fi

# Install jq if not installed already
if [ "$(which jq)" != "" ]; 
then
  echo "jq is already installed"
else
  echo "jq is not installed. Installing jq"
  sudo apt-get install -y jq
fi

new_cl_image="localtestnet"

# ------------------------------------------------
#            Build the Docker Image
# ------------------------------------------------
if [[ "$use_previous_image" == "no" ]]; then
  echo "Using the previously built Docker image"
  echo
  echo -n "Please enter the docker image name (default: localtestnet) "
  read -r cl_image
  if [[ "$cl_image" == "" ]]; then
    new_cl_image="localtestnet"
  else
    new_cl_image=$cl_image
  fi
else
  echo "Starting the Docker Build!"
  # Build the docker Image
  sudo docker build . -t localtestnet
  # The new el_image value
  new_cl_image="localtestnet"
fi


# ------------------------------------------------
#             Run the Kurtosis Tests
# ------------------------------------------------

# Use sed to replace the el_image value in the file
cat kurtosis-network-params.yml | envsubst > assertoor.yaml
sed -i "s/cl_image: .*/cl_image: $new_cl_image/" assertoor.yaml

sudo kurtosis run \
  --enclave nimbus-localtestnet \
  github.com/ethpandaops/ethereum-package \
  --args-file assertoor.yaml

enclave_dump=$(kurtosis enclave inspect nimbus-localtestnet)
assertoor_url=$(echo "$enclave_dump" | grep assertoor | grep http | sed 's/.*\(http:\/\/[0-9.:]\+\).*/\1/')

# ------------------------------------------------
#               Remove Generated File
# ------------------------------------------------
rm assertoor.yaml

# Check the user's input and respond accordingly
if [[ "$reply" == "url" ]]; then
  echo "You chose to visit the assertoor URL."
  echo "Assertoor Checks Please Visit -> ${assertoor_url}"
  echo "Please visit the URL to check the status of the tests"
  echo "The kurtosis enclave needs to be cleared, after the tests are done. Please run the following command ----- sudo kurtosis enclave rm -f nimbus-localtestnet"
else
  echo "Running the checks over terminal"


  # ------------------------------------------------
  #              Check for Test Status
  # ------------------------------------------------
  YELLOW='\033[1;33m'
  GRAY='\033[0;37m'
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  NC='\033[0m'

  # print assertor logs
  assertoor_container=$(docker container list | grep assertoor | sed 's/^\([^ ]\+\) .*$/\1/')
  docker logs -f "$assertoor_container" &

  # helper to fetch task status for specific test id
  get_tasks_status() {
    tasks=$(curl -s "${assertoor_url}"/api/v1/test_run/"$1" | jq -c ".data.tasks[] | {index, parent_index, name, title, status, result}")
    declare -A task_graph_map
    task_graph_map[0]=""

    while read task; do
      task_id=$(echo "$task" | jq -r ".index")
      task_parent=$(echo "$task" | jq -r ".parent_index")
      task_name=$(echo "$task" | jq -r ".name")
      task_title=$(echo "$task" | jq -r ".title")
      task_status=$(echo "$task" | jq -r ".status")
      task_result=$(echo "$task" | jq -r ".result")

      task_graph="${task_graph_map[$task_parent]}"
      task_graph_map[$task_id]="$task_graph |"
      if [ ! -z "$task_graph" ]; then
        task_graph="${task_graph}- "
      fi

      if [ "$task_status" == "pending" ]; then
        task_status="${GRAY}pending ${NC}"
      elif [ "$task_status" == "running" ]; then
        task_status="${YELLOW}running ${NC}"
      elif [ "$task_status" == "complete" ]; then
        task_status="${GREEN}complete${NC}"
      fi

      if [ "$task_result" == "none" ]; then
        task_result="${GRAY}none   ${NC}"
      elif [ "$task_result" == "success" ]; then
        task_result="${GREEN}success${NC}"
      elif [ "$task_result" == "failure" ]; then
        task_result="${RED}failure${NC}"
      fi

      echo -e " $(printf '%-4s' "$task_id")\t$task_status\t$task_result\t$(printf '%-50s' "$task_graph$task_name") \t$task_title"
    done <<< $(echo "$tasks")
  }

  # poll & check test status
  final_test_result=""
  failed_test_id=""
  while true
  do
    pending_tests=0
    failed_tests=0
    total_tests=0
    running_test=""

    status_lines=()
    task_lines=""
    status_lines+=("$(date +'%Y-%m-%d %H:%M:%S')  Test Status:")

    tests=$(curl -s "${assertoor_url}"/api/v1/test_runs | jq -c ".data[] | {run_id, test_id, name, status}")
    while read -r test; do
      if [ -z "$test" ]; then
        continue
      fi
      run_id=$(echo "$test" | jq -r ".run_id")
      test_id=$(echo "$test" | jq -r ".test_id")
      test_name=$(echo "$test" | jq -r ".name")
      test_status=$(echo "$test" | jq -r ".status")

      if [ "$test_status" == "pending" ]; then
        pending_tests=$(expr $pending_tests + 1)
        status_name="${GRAY}pending${NC}"
      elif [ "$test_status" == "running" ]; then
        pending_tests=$(expr $pending_tests + 1)
        running_test="$run_id"
        status_name="${YELLOW}running${NC}"

      elif [ "$test_status" == "success" ]; then
        status_name="${GREEN}success${NC}"
      elif [ "$test_status" == "failure" ]; then
        failed_tests=$(expr $failed_tests + 1)
        failed_test_id="$run_id"
        status_name="${RED}failure${NC}"
      else
        status_name="$test_status"
      fi
      status_lines+=("  $(printf '%-3s' "$test_id") $status_name \t$test_name")
      total_tests=$(expr $total_tests + 1)
    done <<< $(echo "$tests")

    for status_line in "${status_lines[@]}"
    do
      echo -e "$status_line"
    done

    if [ -n "$running_test" ]; then
      task_lines=$(get_tasks_status "$running_test")
      echo "Active Test Task Status:"
      echo "$task_lines"
    fi

    if [ "$failed_tests" -gt 0 ]; then 
      final_test_result="failure"
      break
    fi
    if [ "$total_tests" -gt 0 ] && [ "$pending_tests" -le 0 ]; then
      final_test_result="success"
      break
    fi

    sleep 60
  done

  # save test results & status to github output
  echo "test_result=$(echo "$final_test_result")"
  echo "test_status"
  for status_line in "${status_lines[@]}"
  do
    echo -e "$status_line"
  done
  echo

  if [ -n "$failed_test_id" ]; then
    echo "failed_test_status"
    get_tasks_status "$failed_test_id"
    echo ""
  else
    echo "failed_test_status="
  fi

  # ------------------------------------------------
  #                   Cleanup
  # ------------------------------------------------
  sudo kurtosis enclave rm -f nimbus-localtestnet
fi