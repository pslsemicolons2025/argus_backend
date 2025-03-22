from model import Project, Scan, CVE, Solution, Session
import json
import datetime


def create_project(name: str, project_id, githublink):
    session = Session()
    try:
        project = Project(
            name=name,
            project_id=project_id,
            githublink=githublink
        )
        session.add(project)
        session.commit()
    except Exception as e:
        raise e
    finally:
        session.close()

def project_exist(project_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()
    if project:
        return True
    else:
        return False

def scan_exist(scan_id):
    session = Session()
    scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
    if scan:
        return True
    else:
        return False

def fetch_project_by_id(project_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()
    if project:
        project_data = {
            "id": project.project_id,
            "name": project.name,
            "githublink": project.githublink,
            "scans": []
        }
        for scan in project.scans:
            scan_data = {
                "id": scan.scan_id,
                "related_links": scan.related_links.split(","),
                "tags": scan.tags.split(","),
                "cve": []
            }
            scan
            for cve in scan.cves:
                cve_data = {
                    "cvd_id": cve.cve_id,
                    "description": cve.description,
                    "severity": cve.severity,
                    "category": cve.category,
                    "solutions": cve.solutions,
                    "vulnerability": cve.vulnerability
                }
                scan_data["cve"].append(cve_data)
            if scan.solution:
                solution_data = {
                    "file": scan.solution.file,
                    "comments": scan.solution.comments,
                    "timestamp": scan.solution.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                }
                scan_data["solution"] = solution_data
            project_data["scans"].append(scan_data)
        return json.dumps(project_data, indent=4)
    else:
        return None
    session.close()


def fetch_projects():
    session = Session()
    projects = session.query(Project).all()
    project_json = []
    if projects:
        for project in projects:
            project_data = {
                "projectId": project.project_id,
                "name": project.name,
                "githublink": project.githublink,
                "scans": []
            }
            project_data["scan_count"] = len(project.scans)
            for scan in project.scans:
                scan_data = {
                    "id": scan.scan_id,
                    "related_links": scan.related_links.split(","),
                    "tags": scan.tags.split(","),
                    "cve": []
                }
                project_data["cve_count"] = len(scan.cves)
                for cve in scan.cves:
                    cve_data = {
                        "cvd_id": cve.cve_id,
                        "description": cve.description,
                        "severity": cve.severity,
                        "category": cve.category,
                        "solutions": cve.solutions,
                        "vulnerability": cve.vulnerability
                    }
                    scan_data["cve"].append(cve_data)

                project_data["scans"].append(scan_data)
            project_json.append(project_data)

        return json.dumps(project_json, indent=4)
    else:
        return None
    session.close()

def create_solution(file: str, comments: list, scan_id: str):
    try:
        session = Session()
        solution = Solution(
            file=file,
            comments="|".join(comments),
            scan_id=scan_id,
            timestamp=datetime.datetime.now()
        )

        session.add(solution)
        session.commit()
    except Exception as e:
        raise e
    finally:
        session.close()

def fetch_solution_by_scanid(scan_id):
    session = Session()
    ss = session.query(Solution).filter(Solution.scan_id == scan_id).all()
    solution_data = []
    if ss:
        for s in ss:
            solution = {
                "file": s.file,
                "comments": s.comments.split("|"),
                "scan_id": s.scan_id,
                "timestamp": s.timestamp
            }
            solution_data.append(solution)
        session.close()
        return json.dumps(solution_data, indent=4)
    else:
        session.close()
        return []

def add_solutions_in_bulk(scan_id: str, solutions_data_list: list):
    """
    Adds multiple solutions in bulk to a specified scan.

    :param scan_id: The scan_id for the scan to which the solutions will be added.
    :param solutions_data_list: A list of dictionaries, each containing 'file', 'comments'.
    """
    session = Session()
    try:
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise ValueError(f"No scan found with scan_id {scan_id}")
        solution_objects = []
        for solution_data in solutions_data_list:
            solution = Solution(
                file=solution_data.get("file"),
                comments="|".join(solution_data.get("comments", [])),
                scan_id=scan.scan_id,
                timestamp=datetime.datetime.now()
            )
            solution_objects.append(solution)
        session.add_all(solution_objects)
        session.commit()
        return f"Successfully added {len(solution_objects)} solutions to scan {scan_id}."
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def create_cve(scan_id: str, cve_id: str, severity: str, category: str,description: str, solutions: list, vulnerability: str ):
    session = Session()
    try:
        cve = CVE(
            cve_id = cve_id,
            severity = severity,
            category = category,
            description = description,
            solutions = "|".join(solutions),
            vulnerability = vulnerability,
            scan_id = scan_id
        )
        session.add(cve)
        session.commit()
    except Exception as e:
        raise e
    finally:
        session.close()

def add_cves_in_bulk(scan_id: str, cve_data_list: list):
    session = Session()
    try:
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise ValueError(f"No scan found with scan_id {scan_id}")
        cve_objects = []
        for cve_data in cve_data_list:
            cve = CVE(
                cve_id=cve_data.get("cve_id"),
                severity=cve_data.get("severity"),
                category=cve_data.get("category"),
                solutions="|".join(cve_data.get("solutions", [])),
                vulnerability=cve_data.get("vulnerability"),
                description=cve_data.get("description"),
                scan_id=scan.scan_id
            )
            cve_objects.append(cve)
        session.add_all(cve_objects)
        session.commit()
        return f"Successfully added {len(cve_objects)} CVEs to scan {scan_id}."
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def create_scan(project_id: str, scan_id: str, related_links: list, tags: list, pom: str ):
    session = Session()
    try:
        scan = Scan(
            scan_id = scan_id,
            related_links = "|".join(related_links),
            tags = "|".join(tags),
            project_id = project_id,
            timestamp = datetime.datetime.now(),
            pom = pom
        )
        session.add(scan)
        session.commit()
    except Exception as e:
        raise e
    finally:
        session.close()

def fetch_scans_by_project_id(project_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()

    if project:
        scan_data = []
        for scan in project.scans:
            scan_details = {
                "scan_id": scan.scan_id,
                "related_links": scan.related_links.split(","),
                "tags": scan.tags.split(","),
                "cves": [{"cve_id": cve.cve_id, "severity": cve.severity, "vulnerability": cve.vulnerability, "description": cve.description, "category":cve.category, "solutions":cve.solutions.split("|")} for cve in scan.cves] if scan.cves else [],
                "solution": {
                    "file": scan.solution.file if scan.solution else None,
                    "comments": scan.solution.comments.split("|") if scan.solution else []
                } if scan.solution else None
            }
            scan_data.append(scan_details)
        session.close()
        return json.dumps(scan_data, indent=4) if scan_data else "No scans found"
    else:
        session.close()
        return "No project found"

def fetch_scans_by_scan_id(scan_id):
    session = Session()
    scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()

    if scan:
        scan_details = {
            "scan_id": scan.scan_id,
            "related_links": scan.related_links.split(","),
            "tags": scan.tags.split(","),
            "cves": [{"cve_id": cve.cve_id, "severity": cve.severity, "vulnerability": cve.vulnerability, "description": cve.description, "category":cve.category, "solutions":cve.solutions.split("|")} for cve in scan.cves] if scan.cves else [],
            "solution": {
                "file": scan.solution.file if scan.solution else None,
                "comments": scan.solution.comments.split("|") if scan.solution else []
            } if scan.solution else None
        }

        return json.dumps(scan_details, indent=4) if scan_details else "No scans found"
    else:
        session.close()
        return "No project found"

def fetch_cves_by_project_id(project_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()

    if project:
        cve_data = []
        for scan in project.scans:
            for cve in scan.cves:
                cve_data.append({
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "category": cve.category,
                    "description": cve.category,
                    "vulnerability": cve.category,
                    "solutions": cve.solutions.split("|") if cve.solutions else []
                })
        session.close()
        return json.dumps(cve_data, indent=4) if cve_data else "No CVEs found"
    else:
        session.close()
        return "No project found"


def fetch_latest_solution(project_id, scan_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()

    if project:
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan and scan.solution:
            solution = scan.solution
            solution_data = {
                "file": solution.file,
                "comments": solution.comments.split("|"),
                "timestamp": solution.timestamp
            }
            session.close()
            return json.dumps(solution_data, indent=4)
        else:
            session.close()
            return "No solution found for this scan"
    else:
        session.close()
        return "No project found"


def fetch_latest_scan(project_id):
    session = Session()
    project = session.query(Project).filter(Project.project_id == project_id).first()

    if project:
        latest_scan = session.query(Scan).filter(Scan.project_id == project.project_id).order_by(Scan.id.desc()).first()
        if latest_scan:
            scan_data = {
                "projectName": project.name,
                "projectId": project.project_id,
                "scan_id": latest_scan.scan_id,
                "related_links": latest_scan.related_links.split(","),
                "tags": latest_scan.tags.split(","),
                "cves": [{"cve_id": cve.cve_id, "severity": cve.severity, "vulnerability": cve.vulnerability, "description": cve.description, "category":cve.category, "solutions": cve.solutions.split("|")} for cve in latest_scan.cves] if latest_scan.cves else [],
                "solution": {
                    "file": latest_scan.solution.file if latest_scan.solution else None,
                    "comments": latest_scan.solution.comments.split("|") if latest_scan.solution else []
                } if latest_scan.solution else None
            }
            session.close()
            return json.dumps(scan_data, indent=4)
        else:
            session.close()
            return "No scans found for this project"
    else:
        session.close()
        return "No project found"

def fetch_pom(scan_id: str):
    session = Session()
    scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise ValueError(f"No scan found with scan_id {scan_id}")
    pom = scan.pom
    session.close()
    return pom