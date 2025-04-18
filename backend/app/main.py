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
                circomspect_paths = [
                    "circomspect",
                    "/usr/local/bin/circomspect",
                    "/root/.cargo/bin/circomspect"
                ]
                
                circomspect_found = False
                for circomspect_path in circomspect_paths:
                    try:
                        result = subprocess.run(
                            [circomspect_path, "--sarif-file", sarif_path, file_path],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        circomspect_found = True
                        break
                    except FileNotFoundError:
                        continue
                    except Exception as e:
                        print(f"Error running circomspect: {str(e)}")
                        break
                
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
                    
                    return PlainTextResponse(
                        content=text_report,
                        headers={"Content-Disposition": f"attachment; filename={os.path.splitext(file.filename)[0]}_analysis.txt"}
                    )
                except Exception as e:
                    return PlainTextResponse(f"Error generating text report: {str(e)}")
            
            pdf_path = os.path.join(temp_dir, "analysis_report.pdf")
            generate_pdf_report(sarif_path, pdf_path, file.filename)
            
            if not os.path.exists(pdf_path):
                return {"error": "Failed to generate PDF report"}
            
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
    
    try:
        with open(sarif_path, 'r') as f:
            sarif_data = json.load(f)
        
        if 'runs' in sarif_data:
            for run in sarif_data['runs']:
                if 'tool' in run:
                    tool_info = run['tool']
                    elements.append(Paragraph(f"Tool: {tool_info.get('driver', {}).get('name', 'Circomspect')}", heading_style))
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
    except Exception as e:
        elements.append(Paragraph(f"Error parsing SARIF file: {str(e)}", normal_style))
    
    doc.build(elements)
