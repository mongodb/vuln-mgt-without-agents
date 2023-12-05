# Authenticated Vulnerability Scanning _Without_ Agents

Maintainer: Vincent Zhen (vincent.zhen@mongodb.com)

## Summary

Authenticated vulnerability scanning is traditionally done using dedicated vulnerability scanning agents (e.g., Tenable, Nessus, OpenVAS, NeXpose, Qualys, etc...). These agents provide a good deal of accuracy because the software sits on the actual scan target(s) and checks for applications/binaries and their versions.

However, there may be times when an agent is not the right move for an organization. This can be because of a variety of reasons including lack of personnel to install + administer a vulnerability scanning platform, scan targets being too sensitive to computing resources used by agents, or simply because they don't want any more agents out there.

This repository intends to do "authenticated vulnerability scanning" without using agents. There is an **important caveat** here: **there needs to be a separate method for getting application names and associated versions** whether it be by another agent (e.g., a mobile device management platform that can output application name + version), some other software (e.g., [osquery](https://osquery.io/)), or some cronjob that outputs application name + version somewhere. If and only if this requirement is met, this authenticated vulnerability scanning method can be used.

This repository contains 2 main scripts:

1. `run.py` - Create a mirror of the [National Vulnerability Database (NVD)](https://nvd.nist.gov/vuln) and can keep the mirror up-to-date. 
2. `application-scan-without-agent.py` - Queries your NVD mirror looking for vulnerabilities given application names and associated versions

## Setup

For both creating an NVD mirror and doing authenticated vulnerability scanning without agents, you will need to set up a [MongoDB](https://www.mongodb.com/) instance (I personally used a [MongoDB Atlas](https://www.mongodb.com/cloud) instance because it made installation and setup a lot easier).

You will then need to set up 2 environment variables:

1. `MDB_NVD_HOST` - A [MongoDB URI](https://www.mongodb.com/docs/manual/reference/connection-string/). If you use MongoDB Atlas, this will look like `mongodb+srv://$USERNAME:<password>@mymongodbinstance.random123.mongodb.net` (leave `<password>` like that)
2. `MDB_NVD_PASS` - The password for the user that has access to `MDB_NVD_HOST`
3. `AZURE_OPENAI_URI` - The Azure OpenAI endpoint you are using
4. `AZURE_OPENAI_API_KEY` - The Azure OpenAI API key

(If you don't want to use Azure OpenAI, you can modify the code within the `ask_gai()` function in `application-scan-without-agent.py` script)

To set up environment variables on Linux/MacOS system, do this in a terminal:

```
export MDB_NVD_HOST='mongodb+srv://username:<password>@mymongodbinstance.random123.mongodb.net'
export MDB_NVD_PASS='mypassword123'
```

## Usage

### NVD Mirror

#### Initial Sync

To do an initial sync with the official National Vulnerability Database to create a mirror, do:

```
python run.py --mode initial
```

*NOTE* - An initial sync does a dumb insertion of all CVEs into the database collection. If you do this without dropping the collection first, you will have a lot of duplicates. Only run this once after dumping the collection

#### Keeping NVD Mirror Up-to-date

To keep your NVD mirror up-to-date, do:

```
python run.py --mode update
```

This will look at the ["modified" and "recent"](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) NVD feeds and updates only the CVEs that need updating.

### Authenticated Vulnerability Scanning Without Agents

```
usage: application-scan-without-agent.py [-h] [--bulk-file BULK_FILE] [-a APPLICATION] [-v VERSION] [--debug] [--verbose] [--summary] [-o OUTPUT_FILE] [--no-output-file] [--silent]

optional arguments:
  -h, --help            show this help message and exit
  --bulk-file BULK_FILE
                        A JSON file containing application names and versions you want to look up in bulk
  -a APPLICATION, --application APPLICATION
                        Application name (case insensitive)
  -v VERSION, --version VERSION
                        Version of the application
  --debug               Enable debug logs (same as --verbose)
  --verbose             Enable debug logs (same as --debug)
  --summary             Summarize CVE severities at the end instead of listing every one
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Name of the output file
  --no-output-file      Flag to not create an output file
  --silent              Only output 'ERROR' (or higher) logs
```

#### Examples

To look for CVEs for a specific application and version (here, we want to know what vulnerabilities (if any) affect Teamviewer version 15.20):

```
>$ python application-scan-without-agent.py -a "teamviewer" -v "15.20"
2022-06-24 12:17:31,846 - INFO - Valid CVE: CVE-2022-23242
2022-06-24 12:17:31,847 - INFO - Writing output to teamviewer_cves.json
2022-06-24 12:17:31,847 - INFO - Output: 1 vulnerabilities found for teamviewer 15.20
2022-06-24 12:17:31,847 - INFO - Output: 1 MEDIUM severity vulnerabilities
2022-06-24 12:17:31,847 - INFO -        [CVE-2022-23242] - TeamViewer Linux versions before 15.28 do not properly execute a deletion command for the connection password in case of a process crash. Knowledge of the crash event and the TeamViewer ID as well as either possession of the pre-crash connection password or local authenticated access to the machine would have allowed to establish a remote connection by reusing the not properly deleted connection password.
```

-----

##### To enable debug logs (same as verbose logging):

```
>$ python application-scan-without-agent.py -a "teamviewer" -v "15.20" --debug
```

or 

```
>$ python application-scan-without-agent.py -a "teamviewer" -v "15.20" --verbose
```

-----

##### To do "scanning" of a bulk list of applications and versions:

Set up a JSON file containing the applications and versions. See [example-bulk-file-input.json](example-bulk-file-input.json) for an example.

Then do:

```
>$ python application-scan-without-agent.py --bulk-file example-bulk-file-input.json
```

(change the `--bulk-file` argument to whatever your JSON file is called)

-----

##### To disable outputs to the terminal (except for errors):

```
>$ python application-scan-without-agent.py --bulk-file example-bulk-file-input.json --silent
```

-----

##### To change the output file's name:

```
>$ python application-scan-without-agent.py --bulk-file example-bulk-file-input.json --silent --output-file my-output-file.json
```

-----

##### To output into CSV:

Simply change the `--output-file` to something that ends in `.csv`

```
>$ python application-scan-without-agent.py --bulk-file example-bulk-file-input.json --silent --output-file my-output-file.csv
```

## Disclaimer on Accuracy, False Positives, False Negatives

I've done a fair amount of testing by having a list of known application names and versions, manually checking what CVEs they have in NVD, then using my scripts to see if the output matches my manual investigation. Most of the time it's accurate with few false negatives. I didn't do extensive peer-reviewed testing of this though. If there are false negatives, I would expect that most of the time, it's because my [regex](https://en.wikipedia.org/wiki/Regular_expression) did not pick up on some particular phrasing in the CVE summary or perhaps it's because the "affected CPEs" section is incorrect.

False positives are somewhat high though because if a CVE summary says something like "application XYZ version 1.2.3 on Windows is vulnerable", my script does not pick up that it only affects Windows machines. Additionally, my [regexes](https://en.wikipedia.org/wiki/Regular_expression) may erroneously pick up certain phrases in the CVE summary as a version.

In my cursory analysis, I would say this method has a 75% true positive rate, 40% false positive rate, 90% true negative rate, and 10% false negative rate but I have no evidence to back up these numbers. I encourage you to do your own analysis to see if this method works for you by running some tests yourself.

You will need to critically think in order to figure out what is a true or false positive.

## How It Works

Lots of [regex](https://en.wikipedia.org/wiki/Regular_expression)
