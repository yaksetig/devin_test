from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
import os
import tempfile
import subprocess
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI()

# Disable CORS. Do not remove this for full-stack development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@app.post("/analyze")
async def analyze_circom(file: UploadFile = File(...), format: str = Query("pdf", description="Output format: pdf or txt")):
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        sarif_path = os.path.join(temp_dir, "output.sarif")
        
        try:
            try:
                print("Starting circomspect analysis...")
                
                debug_log_path = os.path.join(temp_dir, "debug_log.txt")
                with open(debug_log_path, 'w') as debug_log:
                    debug_log.write(f"Starting analysis for file: {file_path}\n")
                    debug_log.write(f"Temp directory: {temp_dir}\n")
                    debug_log.write(f"SARIF output path: {sarif_path}\n")
                    
                    debug_log.write("\n--- Environment Info ---\n")
                    try:
                        env_result = subprocess.run(
                            ["env"],
                            capture_output=True,
                            text=True
                        )
                        debug_log.write(f"Environment variables:\n{env_result.stdout}\n")
                    except Exception as e:
                        debug_log.write(f"Error getting environment: {str(e)}\n")
                    
                    circomspect_paths = [
                        "circomspect",
                        "/usr/local/bin/circomspect",
                        "/root/.cargo/bin/circomspect"
                    ]
                    
                    circomspect_found = False
                    for circomspect_path in circomspect_paths:
                        debug_log.write(f"Trying circomspect at {circomspect_path}...\n")
                        try:
                            which_result = subprocess.run(
                                ["which", circomspect_path],
                                capture_output=True,
                                text=True
                            )
                            if which_result.returncode == 0:
                                debug_log.write(f"Found circomspect at: {which_result.stdout.strip()}\n")
                                
                                version_result = subprocess.run(
                                    [circomspect_path, "--version"],
                                    capture_output=True,
                                    text=True
                                )
                                debug_log.write(f"Version check result: {version_result.stdout}\n")
                                
                                debug_log.write(f"Running circomspect on {file_path}...\n")
                                result = subprocess.run(
                                    [circomspect_path, "--sarif-file", sarif_path, file_path],
                                    capture_output=True,
                                    text=True
                                )
                                debug_log.write(f"Circomspect stdout: {result.stdout}\n")
                                debug_log.write(f"Circomspect stderr: {result.stderr}\n")
                                debug_log.write(f"Circomspect return code: {result.returncode}\n")
                                
                                if result.returncode == 0:
                                    debug_log.write("Circomspect ran successfully\n")
                                    circomspect_found = True
                                    break
                                else:
                                    debug_log.write(f"Circomspect failed with return code {result.returncode}\n")
                            else:
                                debug_log.write(f"Binary not found at {circomspect_path}\n")
                        except Exception as e:
                            debug_log.write(f"Error running circomspect: {str(e)}\n")
                            continue
                    
                    if not circomspect_found:
                        debug_log.write("\n--- Building circomspect from source ---\n")
                        circomspect_repo_dir = os.path.join(temp_dir, "circomspect")
                        
                        try:
                            debug_log.write("Cloning circomspect repository...\n")
                            clone_result = subprocess.run(
                                ["git", "clone", "https://github.com/trailofbits/circomspect.git", circomspect_repo_dir],
                                capture_output=True,
                                text=True
                            )
                            debug_log.write(f"Clone stdout: {clone_result.stdout}\n")
                            debug_log.write(f"Clone stderr: {clone_result.stderr}\n")
                            debug_log.write(f"Clone return code: {clone_result.returncode}\n")
                            
                            if clone_result.returncode != 0:
                                debug_log.write("Failed to clone repository\n")
                                raise Exception("Failed to clone circomspect repository")
                            
                            debug_log.write("Building circomspect...\n")
                            build_result = subprocess.run(
                                ["cargo", "build", "--release"],
                                cwd=circomspect_repo_dir,
                                capture_output=True,
                                text=True
                            )
                            debug_log.write(f"Build stdout: {build_result.stdout}\n")
                            debug_log.write(f"Build stderr: {build_result.stderr}\n")
                            debug_log.write(f"Build return code: {build_result.returncode}\n")
                            
                            if build_result.returncode != 0:
                                debug_log.write("Failed to build circomspect\n")
                                raise Exception("Failed to build circomspect")
                            
                            circomspect_bin = os.path.join(circomspect_repo_dir, "target", "release", "circomspect")
                            debug_log.write(f"Checking for binary at {circomspect_bin}\n")
                            
                            if os.path.exists(circomspect_bin):
                                debug_log.write(f"Found circomspect binary at {circomspect_bin}\n")
                                os.chmod(circomspect_bin, 0o755)
                                
                                debug_log.write(f"Running circomspect on {file_path}...\n")
                                result = subprocess.run(
                                    [circomspect_bin, "--sarif-file", sarif_path, file_path],
                                    capture_output=True,
                                    text=True
                                )
                                debug_log.write(f"Circomspect stdout: {result.stdout}\n")
                                debug_log.write(f"Circomspect stderr: {result.stderr}\n")
                                debug_log.write(f"Circomspect return code: {result.returncode}\n")
                                
                                if result.returncode == 0:
                                    debug_log.write("Circomspect ran successfully\n")
                                    circomspect_found = True
                                else:
                                    debug_log.write(f"Circomspect failed with return code {result.returncode}\n")
                            else:
                                debug_log.write("Could not find circomspect binary after build\n")
                                
                                debug_log.write("Installing circomspect using cargo...\n")
                                install_result = subprocess.run(
                                    ["cargo", "install", "--path", os.path.join(circomspect_repo_dir, "cli")],
                                    capture_output=True,
                                    text=True
                                )
                                debug_log.write(f"Install stdout: {install_result.stdout}\n")
                                debug_log.write(f"Install stderr: {install_result.stderr}\n")
                                debug_log.write(f"Install return code: {install_result.returncode}\n")
                                
                                if install_result.returncode != 0:
                                    debug_log.write("Failed to install circomspect\n")
                                    raise Exception("Failed to install circomspect")
                                
                                circomspect_path = "/root/.cargo/bin/circomspect"
                                debug_log.write(f"Running newly installed circomspect on {file_path}...\n")
                                result = subprocess.run(
                                    [circomspect_path, "--sarif-file", sarif_path, file_path],
                                    capture_output=True,
                                    text=True
                                )
                                debug_log.write(f"Circomspect stdout: {result.stdout}\n")
                                debug_log.write(f"Circomspect stderr: {result.stderr}\n")
                                debug_log.write(f"Circomspect return code: {result.returncode}\n")
                                
                                if result.returncode == 0:
                                    debug_log.write("Circomspect ran successfully\n")
                                    circomspect_found = True
                                else:
                                    debug_log.write(f"Circomspect failed with return code {result.returncode}\n")
                        except Exception as e:
                            debug_log.write(f"Error building or running circomspect: {str(e)}\n")
                    
                    if os.path.exists(sarif_path):
                        debug_log.write("\n--- SARIF file created ---\n")
                        with open(sarif_path, 'r') as sarif_file:
                            sarif_content = sarif_file.read()
                            debug_log.write(f"SARIF content:\n{sarif_content}\n")
                    else:
                        debug_log.write("\n--- SARIF file was not created ---\n")
                
                if format.lower() == "txt":
                    with open(debug_log_path, 'r') as debug_log:
                        debug_content = debug_log.read()
                        print(f"Debug log content:\n{debug_content}")
                
                if not circomspect_found:
                    print("Circomspect not found, generating mock data")
                    mock_sarif = generate_mock_sarif(file_path)
                    with open(sarif_path, 'w') as f:
                        json.dump(mock_sarif, f, indent=2)
            except Exception as e:
                print(f"Error running analysis: {str(e)}")
                mock_sarif = generate_mock_sarif(file_path)
                with open(sarif_path, 'w') as f:
                    json.dump(mock_sarif, f, indent=2)
            
            if format.lower() == "txt":
                try:
                    with open(sarif_path, 'r') as f:
                        sarif_content = f.read()
                    
                    text_report = f"Circomspect Analysis Report for {file.filename}\n"
                    text_report += "=" * 50 + "\n\n"
                    
                    sarif_data = json.loads(sarif_content)
                    if 'runs' in sarif_data:
                        for run in sarif_data['runs']:
                            if 'tool' in run:
                                tool_info = run['tool']
                                text_report += f"Tool: {tool_info.get('driver', {}).get('name', 'Circomspect')}\n\n"
                            
                            if 'results' in run:
                                results = run['results']
                                text_report += f"Found {len(results)} issues:\n\n"
                                
                                if results:
                                    for i, result in enumerate(results, 1):
                                        level = result.get('level', 'warning')
                                        rule_id = result.get('ruleId', 'unknown')
                                        
                                        location = "Unknown"
                                        if 'locations' in result and result['locations']:
                                            loc = result['locations'][0]
                                            if 'physicalLocation' in loc:
                                                phys_loc = loc['physicalLocation']
                                                if 'artifactLocation' in phys_loc:
                                                    artifact = phys_loc['artifactLocation'].get('uri', '')
                                                else:
                                                    artifact = ''
                                                
                                                if 'region' in phys_loc:
                                                    region = phys_loc['region']
                                                    start_line = region.get('startLine', '')
                                                    start_col = region.get('startColumn', '')
                                                    location = f"{artifact}:{start_line}:{start_col}"
                                        
                                        message = result.get('message', {}).get('text', 'No message')
                                        
                                        text_report += f"Issue #{i}:\n"
                                        text_report += f"  Level: {level}\n"
                                        text_report += f"  Rule: {rule_id}\n"
                                        text_report += f"  Location: {location}\n"
                                        text_report += f"  Message: {message}\n\n"
                                else:
                                    text_report += "No issues found.\n"
                    
                    text_report += "\n\nRaw SARIF Data:\n"
                    text_report += "=" * 50 + "\n"
                    text_report += sarif_content
                    
                    text_path = os.path.join(temp_dir, f"{os.path.splitext(file.filename)[0]}_analysis.txt")
                    with open(text_path, 'w') as f:
                        f.write(text_report)
                    
                    return FileResponse(
                        path=text_path,
                        media_type="text/plain",
                        filename=f"{os.path.splitext(file.filename)[0]}_analysis.txt"
                    )
                except Exception as e:
                    print(f"Error generating text report: {str(e)}")
                    return PlainTextResponse(
                        content=f"Error generating text report: {str(e)}",
                        headers={"Content-Disposition": f"attachment; filename=error_report.txt"}
                    )
            
            pdf_path = os.path.join(temp_dir, f"{os.path.splitext(file.filename)[0]}_analysis.pdf")
            generate_pdf_report(sarif_path, pdf_path, file.filename)
            
            if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) < 100:
                print("PDF generation failed or created an empty file")
                with open(pdf_path, 'wb') as f:
                    f.write(b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Resources<<>>/Contents 4 0 R/Parent 2 0 R>>endobj 4 0 obj<</Length 21>>stream\nBT /F1 12 Tf 100 700 Td (Error generating report) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n0000000199 00000 n\ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n269\n%%EOF\n')
            
            return FileResponse(
                path=pdf_path,
                media_type="application/pdf",
                filename=f"{os.path.splitext(file.filename)[0]}_analysis.pdf"
            )
        except subprocess.CalledProcessError as e:
            return {"error": f"Analysis failed: {e.stderr}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    except Exception as e:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"error": f"Error processing file: {str(e)}"}

def generate_mock_sarif(file_path):
    """Generate mock SARIF data for when circomspect is not available"""
    filename = os.path.basename(file_path)
    
    mock_sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Circomspect (Mock)",
                        "version": "0.0.0",
                        "informationUri": "https://github.com/trailofbits/circomspect"
                    }
                },
                "results": [
                    {
                        "ruleId": "mock-rule-1",
                        "level": "note",
                        "message": {
                            "text": "This is a mock analysis as circomspect is not available in the current environment."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": filename
                                    },
                                    "region": {
                                        "startLine": 1,
                                        "startColumn": 1
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "mock-rule-2",
                        "level": "warning",
                        "message": {
                            "text": "Mock warning: Consider reviewing your circuit for potential issues."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": filename
                                    },
                                    "region": {
                                        "startLine": 2,
                                        "startColumn": 1
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    return mock_sarif

def generate_pdf_report(sarif_path, pdf_path, filename):
    try:
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12
        )
        
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=10
        )
        
        normal_style = styles['Normal']
        
        elements = []
        
        elements.append(Paragraph(f"Circomspect Analysis Report: {filename}", title_style))
        elements.append(Spacer(1, 12))
        
        with open(sarif_path, 'r') as f:
            sarif_content = f.read()
            sarif_data = json.loads(sarif_content)
        
        if 'runs' in sarif_data:
            for run in sarif_data['runs']:
                if 'tool' in run:
                    tool_info = run['tool']
                    tool_name = tool_info.get('driver', {}).get('name', 'Circomspect')
                    elements.append(Paragraph(f"Tool: {tool_name}", heading_style))
                    elements.append(Spacer(1, 6))
                
                if 'results' in run:
                    results = run['results']
                    elements.append(Paragraph(f"Found {len(results)} issues:", heading_style))
                    elements.append(Spacer(1, 6))
                    
                    if results:
                        data = [["Level", "Rule", "Location", "Message"]]
                        
                        for result in results:
                            level = result.get('level', 'warning')
                            rule_id = result.get('ruleId', 'unknown')
                            
                            location = "Unknown"
                            if 'locations' in result and result['locations']:
                                loc = result['locations'][0]
                                if 'physicalLocation' in loc:
                                    phys_loc = loc['physicalLocation']
                                    artifact = phys_loc.get('artifactLocation', {}).get('uri', '')
                                    
                                    if 'region' in phys_loc:
                                        region = phys_loc['region']
                                        start_line = region.get('startLine', '')
                                        start_col = region.get('startColumn', '')
                                        location = f"{artifact}:{start_line}:{start_col}"
                            
                            message = result.get('message', {}).get('text', 'No message')
                            
                            data.append([level, rule_id, location, message])
                        
                        table = Table(data, colWidths=[60, 100, 100, 240])
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        
                        elements.append(table)
                    else:
                        elements.append(Paragraph("No issues found.", normal_style))
        
        doc.build(elements)
        
        if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) < 100:
            raise Exception("PDF generation failed or created an empty file")
            
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        
        try:
            doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            elements.append(Paragraph(f"Circomspect Analysis Report: {filename}", styles['Title']))
            elements.append(Spacer(1, 12))
            elements.append(Paragraph("Error generating detailed report.", styles['Normal']))
            elements.append(Paragraph(f"Error: {str(e)}", styles['Normal']))
            
            elements.append(Spacer(1, 12))
            elements.append(Paragraph("Raw Analysis Data:", styles['Heading2']))
            
            try:
                with open(sarif_path, 'r') as f:
                    sarif_content = f.read()
                    elements.append(Paragraph(sarif_content, styles['Code']))
            except:
                elements.append(Paragraph("Could not read SARIF data", styles['Normal']))
                
            doc.build(elements)
        except Exception as fallback_error:
            print(f"Fallback PDF generation also failed: {str(fallback_error)}")
            with open(pdf_path, 'wb') as f:
                f.write(b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Resources<<>>/Contents 4 0 R/Parent 2 0 R>>endobj 4 0 obj<</Length 21>>stream\nBT /F1 12 Tf 100 700 Td (Error generating report) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n0000000199 00000 n\ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n269\n%%EOF\n')
