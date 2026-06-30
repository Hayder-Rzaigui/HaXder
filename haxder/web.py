from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List
import uvicorn
import os
import json

from haxder.db import Database
# from haxder.cli import async_main # (Importing this might cause circular import depending on structure, we'll avoid trigger for now to keep UI purely analytical)

app = FastAPI(title="HaXder Enterprise Dashboard")
db = Database()

# Ensure templates directory exists
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    stats = db.get_stats()
    return templates.TemplateResponse("index.html", {"request": request, "stats": stats})

@app.get("/api/graph_data")
async def get_graph_data():
    """
    Transforms the database subdomains into nodes and edges for vis-network.
    """
    data = db.get_all_subdomains()
    
    nodes = []
    edges = []
    
    node_id_map = {}
    current_id = 1
    
    # Add an origin node
    nodes.append({"id": 0, "label": "Internet", "group": "origin", "value": 30})
    
    for base_domain, subdomains in data.items():
        # Create base domain node
        if base_domain not in node_id_map:
            node_id_map[base_domain] = current_id
            nodes.append({"id": current_id, "label": base_domain, "group": "base", "value": 20})
            edges.append({"from": 0, "to": current_id})
            current_id += 1
            
        base_id = node_id_map[base_domain]
        
        # Create subdomain nodes
        for sub in subdomains:
            if sub == base_domain:
                continue
                
            if sub not in node_id_map:
                node_id_map[sub] = current_id
                nodes.append({"id": current_id, "label": sub, "group": "sub", "value": 10})
                edges.append({"from": base_id, "to": current_id})
                current_id += 1

    return {"nodes": nodes, "edges": edges}

class WorkerResult(BaseModel):
    target_domain: str
    subdomains: List[str]

@app.post("/api/worker/submit")
async def receive_worker_results(result: WorkerResult):
    """
    Endpoint for worker nodes to submit their discovered subdomains to the master node.
    """
    if result.target_domain and result.subdomains:
        db.save_subdomains(result.target_domain, set(result.subdomains))
        return {"status": "success", "message": f"Saved {len(result.subdomains)} subdomains."}
    return {"status": "error", "message": "Invalid data"}

def run_server(port: int = 8000, master_mode: bool = False):
    mode_text = "[MASTER NODE]" if master_mode else "[DASHBOARD]"
    print(f"\n[+] Starting HaXder Enterprise Web {mode_text} on http://0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
