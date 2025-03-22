import json
import requests
import logging
import db
import base64
import toml
import re
from fastapi import status
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
ctoml = toml.load("config.toml")
config = ctoml.get("configuration",{})
api = config.get("llm_api")
apikey = config.get("apikey")
pattern = r"(<project[\s\S]*?</project>)"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class CVERequest(BaseModel):
    cve_ids: list[str]
    pom_xml: str

class CVE():
    id: str
    severity: str
    details: str
class RecordScanDetails(BaseModel):
    project_name: str
    project_id: str
    scan_id: str
    git_link: str
    scan_link: list[str]
    cves: list[dict]
    pom_xml: str
    tags: list[str]


HEADERS = {'Authorization': f"Bearer {apikey}"}

logging.basicConfig(filename='app.log', level=logging.DEBUG)

# Function to call Hugging Face LLM model
def call_huggingface_model(pom_xml):
    prompt = f"update the pom.xml file below by fixing the vulnerabilities associated it. The output should be only pom.xml:\n\n{pom_xml}"
    data = {
        "inputs": prompt,
        "parameters": {"return_full_text": False}  # Important to disable prompt echo
    }
    try:
        logging.debug("calling llama with data", data)
        response = requests.post(api, headers=HEADERS, json=data)
        r = response.json()
        logging.debug("llama response", r)
        if type(r) == dict and r.get("error"):
            return { "pom": r.get("error"), "success": False }
        else:
            gt = r[0].get("generated_text")
            l = gt.split("```")
            poms = []
            for i in l:
                if "</project>" in i:
                    poms.append(i)
            final_pom =""
            if len(poms) >1:
                match = re.search(pattern, poms[-1])
                final_pom = match.group(1)
            else:
                match = re.search(pattern, poms[0])
                final_pom = match.group(1)
            logging.debug("final pom",final_pom)
            return { "pom": final_pom, "success": True }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error with Hugging Face API: {str(e)}")

# API endpoint to handle the POST request
@app.post("/v1/addScan/")
async def addScan(scan_details: RecordScanDetails):
    project_name = scan_details.project_name
    project_id = scan_details.project_id
    scan_id = scan_details.scan_id
    git_link = scan_details.git_link
    scan_link = scan_details.scan_link
    cves = scan_details.cves
    pom_xml = scan_details.pom_xml
    tags = scan_details.tags
    if db.project_exist(project_id):
        logging.debug(project_id)
        if not db.scan_exist(scan_id):
            db.create_scan(project_id=project_id, scan_id=scan_id, related_links=scan_link,tags=tags, pom=pom_xml)
        for cve in cves:
            category = cve.get("category") if cve.get("category") else ""
            solutions = cve.get("solutions") if cve.get("solutions") else []
            description = cve.get("description") if cve.get("description") else []
            vulnerability = cve.get("vulnerability") if cve.get("vulnerability") else []
            db.create_cve(description=description, vulnerability=vulnerability,scan_id=scan_id, category=category,cve_id=cve.get("cve_id"), severity=cve.get("severity"), solutions=solutions )
    else:
        logging.debug("Creating new Project")
        db.create_project(githublink=git_link, project_id=project_id, name=project_name)
        if db.project_exist(project_id):
            logging.debug("Project created Successfully")
            logging.debug("Addign scan details")
            if not db.scan_exist(scan_id):
                db.create_scan(project_id=project_id, scan_id=scan_id, related_links=scan_link,tags=tags, pom=pom_xml)
            for cve in cves:
                category = cve.get("category") if cve.get("category") else ""
                solutions = cve.get("solutions") if cve.get("solutions") else []
                description = cve.get("description") if cve.get("description") else []
                vulnerability = cve.get("vulnerability") if cve.get("vulnerability") else []
                db.create_cve(description=description, vulnerability=vulnerability,scan_id=scan_id, category=category,cve_id=cve.get("cve_id"), severity=cve.get("severity"), solutions=solutions )
    project_output = json.loads(db.fetch_project_by_id(project_id))
    return project_output



@app.get("/v1/latestScan/")
async def getLatestScan(project_id: str):
    if project_id:
        latest_scan = db.fetch_latest_scan(project_id=project_id)
        output_json = json.loads(latest_scan)
        return output_json
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required parameter missing project_id")



@app.get("/v1/getScansByProjectId/")
async def getLatestScanByProjectId(project_id: str):
    if project_id:
        latest_scan = db.fetch_scans_by_project_id(project_id=project_id)
        output_json = json.loads(latest_scan)
        return output_json
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required parameter missing project_id")


@app.get("/v1/latestScanByScanId/")
async def getLatestScanByScanId(scan_id: str):
    if scan_id:
        latest_scan = db.fetch_scans_by_scan_id(scan_id=scan_id)
        output_json = json.loads(latest_scan)
        return output_json
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required parameter missing scan_id")



@app.get("/v1/getllmfix/")
async def getllmfix(scan_id: str):
    if scan_id:
        llmFix(scan_id)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required parameter missing scan_id")


def llmFix(scan_id: str):
    if scan_id:
        pom = db.fetch_pom(scan_id=scan_id)
        decoded_pom = b64decode(pom)
        result_pom = ""
        comments = []
        result = call_huggingface_model(decoded_pom)
        if result.get("success"):
            result_pom = result.get("pom")
        else:
            comments.append("Unable to get Fixed POM.XML please try /v1/getllmfix/ API to get fixed pom.xml")
        encoded_pom = b64encode(result_pom)
        db.create_solution(file=encoded_pom,comments=comments, scan_id=scan_id)
        return result
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required parameter missing scan_id")


@app.get("/v1/allProjects/")
async def allProjects():
    projects = db.fetch_projects()
    output_json = json.loads(projects)
    return output_json

def b64encode(s):
    base64_bytes = s.encode("ascii")
    base64_bytes = base64.b64encode(base64_bytes)
    encoded_string = base64_bytes.decode("ascii")
    return encoded_string

def b64decode(s):
    base64_bytes = s.encode("ascii")
    base64_bytes = base64.b64decode(base64_bytes)
    decoded_string = base64_bytes.decode("ascii")
    return decoded_string
