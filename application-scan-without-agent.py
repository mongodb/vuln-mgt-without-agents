#!/usr/bin/python

import pymongo
import logging
import argparse
from os import environ as env
import json
import re
import openai
from ast import literal_eval

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
logger.addHandler(s_handler)

"""
Simply connect to MongoDB
* Requires environment variables to be set which specifies the URI to connect to MongoDB and the password
"""
def connect_mdb():
    connection_str = env["MDB_NVD_HOST"].strip()
    db = "nvd_mirror"
    pw = env["MDB_NVD_PASS"].strip()
    user = env["MDB_NVD_USER"].strip()
    connection_str = f"mongodb+srv://{user}:{pw}@{connection_str}"
    try:
        conn = pymongo.MongoClient(connection_str)
        logger.debug("Connected to MongoDB Atlas")
    except Exception as e:
        logger.error("Unable to get a connection to the MongoDB database: {}".format(e))
        exit(1)
    return conn

"""
Checks to see which version is greater
"""
def greater_version(source, target):
    # First extend the version
    source = str(source)
    target = str(target)
    pattern = r'\D+'
    s = re.split(pattern, source)
    t = re.split(pattern, target)
    s = [int(_) if _ else 0 for _ in s]
    t = [int(_) if _ else 0 for _ in t]
    if len(s) > len(t):
        t.extend([0] * (len(s) - len(t)))
    else:
        s.extend([0] * (len(t) - len(s)))
    for i in range(0, len(s)):
        if s[i] > t[i]:
            return source
        elif t[i] > s[i]:
            return target
    # Default
    return source


# Finds all CVEs that reference this CPE
# BULK VERSION: def find_all_cves(conn, application, versions, debug=False):
def find_all_cves(conn, application, versions, debug=False):
    db = conn["nvd_mirror"]
    coll = db["cves"]

    def normalize_app_name(application):
        output = ""
        for letter in application:
            if letter in '!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~':
                output += f".?{letter}.?"
            else:
                output += letter
        output = output.lower().replace(" ", ".{0,3}")
        output = output.replace("*", ".")
        return output

    normalized_app = normalize_app_name(application)
    # First, we get all CVEs that reference this application
    query = {
            "cve.description.description_data": {
                "$elemMatch": {
                    "value": {
                        "$regex": f"(\s|^){normalized_app}(\s|$)", 
                        "$options": "si"
                        }
                    }
                }
            }

    logger.debug(f"Application to look up: {application}")
    logger.debug(f"Query: {json.dumps(query)}")

    def is_app_in_cpe_uri(uri):
        normalized_app = application.lower()
        pattern = r'\W+'
        split_app = re.split(pattern, normalized_app)
        application_part_of_uri = ':'.join(uri.split(':')[3:5])
        for x in split_app:
            if x not in application_part_of_uri:
                return False
        return True

    def ask_gai(application, version, found_cves):
        client = openai.AzureOpenAI(
                api_key = env["AZURE_OPENAI_API_KEY"],
                api_version = "2023-05-15",
                azure_deployment = "Inference",
                azure_endpoint = "http://localhost:8000/api-chat-3/azure"
                )

        prompt = """Given application '""" + application + """' that is version '""" + version + """' and the JSON blob below containing a list of CVE IDs and descriptions, give me a list of CVE IDs that affect this application and version. Give the answer only in a Python list format without anything else. If there are no valid CVEs or if based on the information given the answer is still unknown, simply respond with an empty Python list.\n\n-----\n\n""" + json.dumps(found_cves)
        logger.debug(f"GAI prompt: {prompt}")

        completion = client.chat.completions.create(
          model="gpt-3.5-turbo",
          n=1,
          temperature=0,
          messages=[
            {"role": "system", "content": "You are a simple bot that evaluates whether or not an application is affected by vulnerabilities based on the JSON descriptions below. You only respond in a way where Python can ingest the response (like a Python list)."},
            {"role": "user", "content": prompt}
          ]
        )

        gai_answer = completion.choices[0].message.content
        logger.debug(f"GAI answer: {gai_answer}")
        return gai_answer

    def is_valid_cve(application, version, cve_id, description, cpe_match):
        logger.debug("-----")
        # `confidences` is the output
        confidences = dict()

        # This is what we initially regex for so this must be true
        logger.debug(f"[{cve_id}] - Summary contains application name. +confidence")
        confidences["summary contains app name"] = True

        # This is another validity metric which asks if the CPE URI helps us determine the version validity
        if cpe_match["vulnerable"]:
            cpe_uri = cpe_match["cpe23Uri"]
            if is_app_in_cpe_uri(cpe_uri):
                # This is a validity metric where we simply look for the application in the CPE URI as a string
                logger.debug(f"[{cve_id}] - Application in CPE URI. +confidence")
                confidences["app in cpe_uri"] = True
                if cpe_uri.split(":")[5] != "*":
                    version_start = cpe_uri.split(":")[5]
                    version_end = cpe_uri.split(":")[5]
                    if version_start == "-":
                        version_start = 0
                    if version_end == "-":
                        version_end = 9999999999999
                else:
                    try:
                        version_start_including = cpe_match["versionStartIncluding"]
                    except KeyError:
                        version_start_including = None
                    try:
                        version_end_including = cpe_match["versionEndIncluding"]
                    except KeyError:
                        version_end_including = None
                    try:
                        version_start_excluding = cpe_match["versionStartExcluding"]
                    except KeyError:
                        version_start_excluding = None
                    try:
                        version_end_excluding = cpe_match["versionEndExcluding"]
                    except KeyError:
                        version_end_excluding = None

                    if version_start_including is None:
                        if version_start_excluding is None:
                            version_start = 0
                        else:
                            version_start = version_start_excluding
                    else:
                        version_start = version_start_including
                    if version_end_including is None:
                        if version_end_excluding is None:
                            version_end = 999999999999
                        else:
                            version_end = version_end_excluding
                    else:
                        version_end = version_end_including
                greater_start_version = greater_version(str(version), str(version_start))
                greater_end_version = greater_version(str(version), str(version_end))

                if str(greater_start_version) == str(version) and str(greater_end_version) == str(version_end):
                    logger.debug(f"[{cve_id}] - Evaluated CPE: {version_start} <= {version} <= {version_end}. +confidence")
                    confidences["cpe_version_eval"] = True
                elif "cpe_version_eval" not in confidences.keys():
                    logger.debug(f"[{cve_id}] - Evaluated CPE _INVALID_: {version_start} <= {version} <= {version_end}. -confidence")
                    confidences["cpe_version_eval"] = False

        # This metric uses regex to go through the summary of the CVE and checks for the version validity that way
        regexes = {
                # Between versions
                "((v?\d\S*?)(\sthrough\s)(v?\d\S*?)(\s|$))|((version|versions)\s(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(between\s(version\s|versions\s)?(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(before\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?after\s(version\s|versions\s)?(v?\d\S*?)(\s|$))|(after\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?before\s(version\s|versions\s)?(v?\d\S*?)(\s|$))": "between",
                # Before versions
                "(((versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(versions\s)?)(v?\d\S*?)(,(\s(and\s)?(v?\d\S*))+))|((((version\s|versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(version\s|versions\s)?)|(<(=)?\s+?))(v?\d\S*?)(\s|$)(?!and\safter))|(version|versions)?(\s(v?\d\S*?)\s(\()?and\s(below|prior|before|earlier)(\))?)": "before",
                # After versions
                "(?!and)\s((((after)\s(version\s|versions\s)?)|(>(=)?\s+?))(v?\d\S*?)(\s|$)(?!and))|(\s(v?\d\S?)\s(\()and\s(after|later)(\)))": "after",
                # Raw versions
                "(\s(version\s)?(v?\d\S*?)(\s|$)(?!and))": "raw"
                }
        version_re = "v?\d\S*"
        need_raw = True
        regex_found = False
        found_regexes = list()
        for regex in regexes.keys():
            if not regex_found:
                descr_re_result = re.findall(regex, description, flags=re.I|re.M)
                if descr_re_result:
                    if regexes[regex] == "raw":
                        if need_raw:
                            pass
                        else:
                            continue
                    regex_hit_type = regexes[regex].upper()
                    for result in descr_re_result:
                        versions_in_result = set()
                        # Search through the items in the groups
                        if not regex_found:
                            for r in result:
                                if r:
                                    regex_subsearch = re.search(version_re, r, flags=re.I|re.M)
                                    if regex_subsearch:
                                        if regex_subsearch.group()[-1] in '!"#$%&\'()*+, -./:;<=>?@[\]^_`{|}~':
                                            subsearch_results = regex_subsearch.group()[:-1].strip()
                                        else:
                                            subsearch_results = regex_subsearch.group().strip()
                                        if subsearch_results.startswith('v'):
                                            subsearch_results = subsearch_results[1:]
                                        versions_in_result.add(subsearch_results)
                                        need_raw = False
                            versions_in_result = list(versions_in_result)
                            if regex_hit_type == "BETWEEN":
                                # If there's only 1 "version in result" for a "between" hit, we will use it as a regular raw
                                if len(versions_in_result) == 1:
                                    versions_in_result = [versions_in_result[0]] * 2
                                found_regexes.append("BETWEEN")
                                version_end = greater_version(versions_in_result[0], versions_in_result[1])
                                if version_end == versions_in_result[0]:
                                    version_start = versions_in_result[1]
                                else:
                                    version_start = versions_in_result[0]
                                if greater_version(version_start, version) == version and greater_version(version_end, version) == version_end:
                                    logger.debug(f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_start} <= {version} <= {version_end}. +confidence")
                                    confidences["summary regex eval"] = True
                                    regex_found = True
                                else:
                                    logger.debug(f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_start} <= {version} <= {version_end}")
                            if regex_hit_type == "BEFORE":
                                found_regexes.append("BEFORE")
                                for version_in_result in versions_in_result:
                                    if greater_version(version_in_result, version) == version_in_result:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version} < {version_in_result}. +confidence")
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version} < {version_in_result}")
                            if regex_hit_type == "AFTER":
                                found_regexes.append("AFTER")
                                for version_in_result in versions_in_result:
                                    if greater_version(version_in_result, version) == version:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_in_result} < {version}. +confidence")
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_in_result} < {version}")
                            if regex_hit_type == "RAW" and need_raw:
                                found_regexes.append("RAW_VERSION")
                                for version_in_result in versions_in_result:
                                    if version_in_result == version:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_in_result} == {version}. +confidence")
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_in_result} == {version}")

        try:
            confidences["summary regex eval"]
        except KeyError:
            logger.debug(f"[{cve_id}] - Summary regex evaluation did not get a verison match (found regexes: {', '.join(found_regexes)}). -confidence")
            confidences["summary regex eval"] = False
        try:
            confidences["app in cpe_uri"]
        except KeyError:
            logger.debug(f"[{cve_id}] - Application not in CPE URI. -confidence")
            confidences["app in cpe_uri"] = False
        try:
            confidences["cpe_version_eval"]
        except KeyError:
            logger.debug(f"[{cve_id}] - Did not do CPE version evaluation due to invulnerable CPE or application not in CPE URI. -confidence")
            confidences["app in cpe_uri"] = False
        confidences["gai says yes"] = False
        return confidences

    def populate_candidate_cves(cves, versions):
        logger.info(f"Evaluating {application} with version(s) {', '.join(versions)}")
        normalized_cves = dict()
        candidate_cves = dict()
        for version in versions:
            candidate_cves[version] = dict()
        for cve in cves:
            nodes = cve["configurations"]["nodes"]
            logger.debug(f"------------ [{cve['cve']['CVE_data_meta']['ID']}] -------------")
            logger.debug(f"Description: {cve['cve']['description']['description_data'][0]['value']}")
            normalized_cves[cve['cve']['CVE_data_meta']['ID']] = cve['cve']['description']['description_data'][0]['value']
            for version in versions:
                logger.debug(f"Evaluating {application} CVEs for version {version}")
                for node in nodes:
                    for child in node["children"]:
                        cpe_matches = child["cpe_match"]
                        for cpe_match in cpe_matches:
                            if cve["cve"]["CVE_data_meta"]["ID"] not in candidate_cves.keys():
                                logger.debug(f"CPE: {cpe_match}")
                                candidate_cves[version][cve["cve"]["CVE_data_meta"]["ID"]] = is_valid_cve(application, version, cve["cve"]["CVE_data_meta"]["ID"], cve["cve"]["description"]["description_data"][0]["value"], cpe_match)
                    cpe_matches = node["cpe_match"]
                    for cpe_match in cpe_matches:
                        if cve["cve"]["CVE_data_meta"]["ID"] not in candidate_cves.keys():
                            logger.debug(f"CPE: {cpe_match}")
                            candidate_cves[version][cve["cve"]["CVE_data_meta"]["ID"]] = is_valid_cve(application, version, cve["cve"]["CVE_data_meta"]["ID"], cve["cve"]["description"]["description_data"][0]["value"], cpe_match)

        for version in versions:
            logger.info(f"Getting GAI answer for {application}, version {version}")
            gai_ans = ask_gai(application, version, normalized_cves)
            try:
                gai_ans = literal_eval(gai_ans)
                for a in gai_ans:
                    candidate_cves[version][cve["cve"]["CVE_data_meta"]["ID"]]["gai says yes"] = True

            except:
                logger.error(f"Unable to cast GAI response: {gai_ans}, as anything that could be literal_eval'ed")
        return candidate_cves

    def get_valid_cves(candidate_cves_with_versions, cve_details):
        WEIGHTS = {
           "summary contains app name": 2,
           "app in cpe_uri": 2,
           "cpe_version_eval": 2,
           "summary regex eval": 2,
           "gai says yes": 5 
        }
        THRESHOLD = sum(WEIGHTS.values()) / 2
        valid_cves = dict()
        for version, candidate_cves in candidate_cves_with_versions.items():
            valid_cves[version] = set()
            for candidate_cve, confidences in candidate_cves.items():
                score = 0
                for confidence_name, confidence_value in confidences.items():
                    score += WEIGHTS[confidence_name] * int(confidence_value)
                if score >= THRESHOLD:
                    valid_cves[version].add(candidate_cve) 
        ans = dict()
        for version, valid_cve_set in valid_cves.items():
            ans[version] = dict()
            for valid_cve in valid_cve_set: 
                for cve_detail in cve_details:
                    if cve_detail["cve"]["CVE_data_meta"]["ID"] == valid_cve:
                        ans[version][valid_cve] = cve_detail
        return ans

    # TODO - do bulk version of this
    valid_cves = dict()
    cve_count = coll.count_documents(query)
    logger.debug(f"MongoDB returned {cve_count} documents for the query")
    # Load the CVEs into a list so we don't have to use a cursor due to 10 minute timeouts
    cves = [_ for _ in coll.find(query)]
    #cves = [_ for _ in coll.aggregate(query)]
    candidate_cves_with_versions = populate_candidate_cves(cves, versions)
    valid_cves = get_valid_cves(candidate_cves_with_versions, cves)
    return valid_cves

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bulk-file", help="A JSON file containing application names and versions you want to look up in bulk")
    parser.add_argument("-a", "--application", help="Application name (case insensitive)")
    parser.add_argument("-v", "--version", help="Version of the application")
    parser.add_argument("--debug", action='store_true', help="Enable debug logs (same as --verbose)")
    parser.add_argument("--verbose", action='store_true', help="Enable debug logs (same as --debug)")
    parser.add_argument("--summary", action='store_true', help="Summarize CVE severities at the end instead of listing every one")
    parser.add_argument("-o", "--output-file", help="Name of the output file")
    parser.add_argument("--no-output-file", action='store_true', help="Flag to not create an output file")
    parser.add_argument("--silent", action='store_true', help="Only output 'ERROR' (or higher) logs")
    args = parser.parse_args()

    if args.silent:
        logger.setLevel(logging.ERROR)
    if args.debug or args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.debug("Debug/Verbose mode: ON")
    # Set up required arguments
    if not args.bulk_file:
        if args.application:
            if not args.version:
                logger.error("-a/--application requires -v/--version")
                exit(1)
        elif args.version:
            if not args.application:
                logger.error("-v/--version requires -a/--application")
                exit(1)
        else:
            logger.error("-a/--application and -v/--version required, or --bulk-file required")
            exit(1)

    if not args.no_output_file:
        # Set up a default output file name
        if not args.output_file and args.application and args.version:
            a = ''.join([c for c in args.application if re.match(r'\w', c)])
            args.output_file = f"{a}_cves.json"
        elif not args.output_file and args.bulk_file:
            args.output_file = "bulk_cves.json"
        # You should never hit this but I'll default it just in case
        elif not args.output_file:
            args.output_file = "default.json"
    logger.debug(f"Output file: {args.output_file}")

    # Set up arguments
    if args.bulk_file:
        with open(args.bulk_file, 'r') as infile:
            inputs = json.loads(infile.read())
    else:
        inputs = {args.application: [args.version]}

    conn = connect_mdb()
    cve_dict = dict()
    for application, versions in inputs.items():
        cves = find_all_cves(conn, application, versions, args.debug)
        cve_dict[application] = cves

    summary = list()
    # Output to terminal
    for application, version_and_dict in cve_dict.items():
        for version, sub_cves in version_and_dict.items():
            total_cve_count = 0
            severity_dict = dict()
            for cve_id, cve in sub_cves.items():
                total_cve_count += 1
                try:
                    severity = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                except KeyError:
                    severity = cve["impact"]["baseMetricV2"]["severity"]
                if severity not in severity_dict.keys():
                    severity_dict[severity] = list()
                severity_dict[severity].append(cve)
                summary.append({"application": application,
                    "version": version,
                    "cve": cve_id,
                    "severity": severity,
                    "description": cve['cve']['description']['description_data'][0]['value'],
                    "NVD URL": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})

            logger.debug("------------------------------")
            logger.info(f"{total_cve_count} vulnerabilities found for {application} {version}")
            for severity, cves in severity_dict.items():
                logger.info(f"- {len(cves)} {severity} severity vulnerabilities")
                for cve in cves:
                    if not args.summary:
                        logger.info(f"\t[{cve['cve']['CVE_data_meta']['ID']}] - {cve['cve']['description']['description_data'][0]['value']}")

    if not args.no_output_file:
        assert args.output_file is not None
        with open(args.output_file, 'w') as outfile:
            if len(summary) == 0:
                logger.info("No vulnerabilities to write. Writing empty file")

            elif args.output_file.endswith('.csv'):
                logger.info(f"Writing summary output to {args.output_file}")
                import csv
                dict_writer = csv.DictWriter(outfile, summary[0].keys())
                dict_writer.writeheader()
                dict_writer.writerows(summary)
            else:
                if args.summary:
                    logger.info(f"Writing summary output to {args.output_file}")
                    outfile.write(json.dumps(summary))
                else:
                    logger.info(f"Writing full output to {args.output_file}")
                    outfile.write(json.dumps(cve_dict, default=str))

    logger.debug("Closing MongoDB connection")
    conn.close()
    logger.debug("Script complete")
