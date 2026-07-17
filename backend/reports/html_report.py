import os
from jinja2 import Environment, FileSystemLoader
from backend.utils.severity import calculate_security_score

def generate_html_report(project, scan, vulnerabilities) -> str:
    """
    Renders the Jinja2 HTML template with the project results.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "templates")
    
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("report.html")
    
    score = calculate_security_score(vulnerabilities)
    
    rendered = template.render(
        project=project,
        scan=scan,
        vulnerabilities=vulnerabilities,
        files=project.files,
        security_score=score
    )
    return rendered
