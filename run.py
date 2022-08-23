#!/usr/bin/python

import pymongo
import logging
import argparse
from os import environ as env
from datetime import datetime
import pytz
import requests
import gzip
import io
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
logger.addHandler(s_handler)

def connect_mdb():
    connection_str = env["MDB_NVD_HOST"].strip()
    db = "nvd_mirror"
    pw = env["MDB_NVD_PASS"].strip()
    connection_str = connection_str.replace("<password>", pw)
    connection_str = connection_str.replace("<dbname>", db)
    try:
        conn = pymongo.MongoClient(connection_str)
        logger.info("Connected to MongoDB Atlas!")
    except Exception as e:
        logger.error("Unable to get a connection to the MongoDB database: {}".format(e))
        exit(1)
    return conn

# Download metadata files
def get_metafiles():
    this_year = datetime.today().year
    output = dict()
    for year in range(2002, this_year + 1):
        link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta"
        logger.info(f"Getting meta file: {link}")
        res = requests.get(link)
        output[year] = dict()
        metadata = res.text.split()
        for _ in metadata:
            _ = _.split(":")
            output[year][_[0]] = ':'.join(_[1:])
        output[year]['lastModifiedDate'] = datetime.strptime(output[year]['lastModifiedDate'], "%Y-%m-%dT%H:%M:%S%z")
    return output        

# Only the CVE files that were updated need to be downloaded
def eval_needed_updates(conn):
    metafiles = get_metafiles()
    checkpoints = get_checkpoints(conn)
    years_need_updates = list()
    utc = pytz.UTC
    for year, metadata in metafiles.items():
        if year not in checkpoints.keys() or metadata["lastModifiedDate"].replace(tzinfo=utc) > checkpoints[year].replace(tzinfo=utc):
            years_need_updates.append(year)
            logger.info(f"New updates available for {year}")
    return (years_need_updates, metafiles)

# Download specific CVE year
def get_nvd_part(year):
    logger.info(f"Getting CVEs for year {year}")
    link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
    res = requests.get(link, timeout=60, stream=True)
    # Gunzip in memory
    gz_file = res.content
    fd = io.BytesIO(gz_file)
    with gzip.GzipFile(fileobj=fd) as f:
        return json.loads(f.read())["CVE_Items"]
    logger.error(f"Unable to get CVEs for year {year} or failed gunzipping it")
    return [""]

# Wrapper to download all CVE years
def download_and_upsert_nvd(years_need_updates, t="sync"):
    db = conn["nvd_mirror"]
    coll = db["cves"]
    for year in years_need_updates:
        data = get_nvd_part(year)
        logger.info(f"{year} has {len(data)} CVEs to insert")
        # Sync by updating only the specific CVEs that need updating
        if t == "sync":
            ops = [pymongo.operations.ReplaceOne(filter={"cve.CVE_data_meta.ID": doc["cve"]["CVE_data_meta"]["ID"]},
                replacement = doc,
                upsert = True) for doc in data]
            result = coll.bulk_write(ops)
            logger.info(f"Done inserting: {result.bulk_api_result}")
        # Just insert if we're doing the initial data dump
        elif t == "initial":
            coll.insert_many(data) 
            logger.info(f"Done inserting {len(data)} items")
        logger.info(f"Finished inserting {year}'s CVEs")

def get_checkpoints(conn):
    db = conn["nvd_mirror"]
    coll = db["meta"]
    checkpoints = coll.find({"type": "cve checkpoint"}, {"feed": 1, "lastModifiedDate": 1})
    output = dict()
    for checkpoint in checkpoints:
        output[checkpoint['feed']] = checkpoint['lastModifiedDate']
    return output

def update_checkpoint(conn, metafiles):
    db = conn["nvd_mirror"]
    coll = db["meta"]
    for feed, metadata in metafiles.items():
        metadata["feed"] = feed
        coll.update_one({"type": "cve checkpoint", "feed": feed}, {"$set": metadata}, upsert=True)
        logger.info(f"Checkpoint for feed {feed} is updated")

def get_special(conn, feed):
    assert feed in ['modified', 'recent']
    link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{feed}.meta"
    logger.info(f"Getting meta file: {link}")
    res = requests.get(link)
    metadata = dict()
    o = res.text.split()
    for _ in o:
        _ = _.split(":")
        metadata[_[0]] = ':'.join(_[1:])
    metadata['lastModifiedDate'] = datetime.strptime(metadata['lastModifiedDate'], "%Y-%m-%dT%H:%M:%S%z")
    metadata['feed'] = feed
    metadata = {feed: metadata}
    checkpoints = get_checkpoints(conn)
    utc = pytz.UTC
    if feed not in checkpoints.keys() or checkpoints[feed].replace(tzinfo=utc) < metadata[feed]['lastModifiedDate'].replace(tzinfo=utc):
        logger.info(f"Updates available in the '{feed}' feed")
        link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{feed}.json.gz"
        res = requests.get(link, timeout=60, stream=True)
        # Gunzip in memory
        gz_file = res.content
        fd = io.BytesIO(gz_file)
        with gzip.GzipFile(fileobj=fd) as f:
            data = json.loads(f.read())["CVE_Items"]
        logger.info(f"'{feed}' feed has {len(data)} items to insert")
        db = conn["nvd_mirror"]
        coll = db["cves"]
        ops = [pymongo.operations.ReplaceOne(filter={"cve.CVE_data_meta.ID": doc["cve"]["CVE_data_meta"]["ID"]},
            replacement = doc,
            upsert = True) for doc in data]
        result = coll.bulk_write(ops)
        logger.info(f"Done inserting: {result.bulk_api_result}")
        update_checkpoint(conn, metadata)
        return True
    else:
        logger.info(f"No updates to the '{feed}' feed. Latest update was at {str(checkpoints[feed])}")
        return False

def get_cpe_feed(conn, t='sync'):
    assert t in ["sync", "initial"]
    feed = 'cpe'
    link = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.meta"
    logger.info(f"Getting meta file: cpe")
    res = requests.get(link)
    metadata = dict()
    o = res.text.split()
    for _ in o:
        _ = _.split(":")
        metadata[_[0]] = ':'.join(_[1:])
    metadata['lastModifiedDate'] = datetime.strptime(metadata['lastModifiedDate'], "%Y-%m-%dT%H:%M:%S%z")
    metadata['feed'] = feed
    metadata = {feed: metadata}
    checkpoints = get_checkpoints(conn)
    utc = pytz.UTC
    if feed not in checkpoints.keys() or checkpoints[feed].replace(tzinfo=utc) < metadata[feed]['lastModifiedDate'].replace(tzinfo=utc):
        logger.info(f"Updates available in the 'cpe' feed")
        link = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
        res = requests.get(link, timeout=60, stream=True)
        # Gunzip in memory
        gz_file = res.content
        fd = io.BytesIO(gz_file)
        with gzip.GzipFile(fileobj=fd) as f:
            data = json.loads(f.read())["matches"]
        logger.info(f"'{feed}' feed has {len(data)} items to insert")
        db = conn["nvd_mirror"]
        coll = db["cpes"]
        """
        if t == "sync":
            ops = [pymongo.operations.ReplaceOne(filter={"cpe23Uri": doc["cpe23Uri"]},
                replacement = doc,
                upsert = True) for doc in data]
            result = coll.bulk_write(ops)
            logger.info(f"Done inserting: {result.bulk_api_result}")
        """
        coll.drop()
        coll.insert_many(data) 
        logger.info(f"Done inserting {len(data)} items")
        update_checkpoint(conn, metadata)
        return True
    else:
        logger.info(f"No updates to the 'cpe' feed. Latest update was at {str(checkpoints['cpe'])}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="One of 'initial', 'sync', or 'update'\n\t'initial' - dumbly insert all of the CVEs from NVD into MongoDB\n\t'sync' - download whole years worth of CVEs and replace them all if they've been updated recently\n\t'update' - use the \"modified\" and \"recent\" JSON blobs to target which CVEs to update", required=True)
    parser.add_argument("-t", "--type", help='either cve or cpe type to get data for', default="cve")
    args = parser.parse_args()
    args.mode = args.mode.lower().strip()
    if args.type == "cve":
        if args.mode == "initial":
            # Below is for initial sync
            conn = connect_mdb()
            years_need_updates, metafiles = eval_needed_updates(conn)
            download_and_upsert_nvd(years_need_updates, t="initial")
            update_checkpoint(conn, metafiles)
            conn.close()
            logger.info("Atlas connection closed. Done!")
        elif args.mode == "sync":
            conn = connect_mdb()
            years_need_updates, metafiles = eval_needed_updates(conn)
            download_and_upsert_nvd(years_need_updates, t="sync")
            update_checkpoint(conn, metafiles)
            conn.close()
            logger.info("Atlas connection closed. Done!")
        elif args.mode == "update":
            conn = connect_mdb()
            get_special(conn, 'modified')
            get_special(conn, 'recent')
            conn.close()
            logger.info("Atlas connection closed. Done!")
        else:
            logger.error("--mode must be one of 'initial', 'sync', or 'update'")
            exit(1)
    elif args.type == "cpe":
        conn = connect_mdb()
        get_cpe_feed(conn, t="initial")
        conn.close()
        logger.info("Atlas connection closed. Done!")
