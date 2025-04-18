from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
async def analyze_circom(file: UploadFile = File(...)):
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        sarif_path = os.path.join(temp_dir, "output.sarif")
        
        try:
            result = subprocess.run(
                ["circomspect", "--sarif-file", sarif_path, file_path],
                capture_output=True,
                text=True,
                check=True
            )
            
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
