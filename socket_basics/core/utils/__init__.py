import json

__all__ = [
    "make_json_safe",
    "is_trivy_dockerfile",
]

def make_json_safe(value: str) -> str:
    """
    Make a string JSON-safe by escaping special characters.
    
    Args:
        value: The string to make JSON-safe
        
    Returns:
        A JSON-safe string with proper escaping
    """
    if not isinstance(value, str):
        return value
    
    # Use json.dumps to properly escape the string, then remove the surrounding quotes
    return json.dumps(value)[1:-1]

def is_trivy_dockerfile(component: dict) -> bool:
    """Check if a Trivy component represents a Dockerfile vulnerability.
    
    Dockerfile components have direct=True and no ecosystem qualifier.
    Image package components have direct=False and an ecosystem qualifier.
    """
    comp_direct = component.get('direct', False)
    has_ecosystem = bool(component.get('qualifiers', {}).get('ecosystem'))
    return comp_direct and not has_ecosystem