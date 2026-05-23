def resp_success(data: dict = None, msg: str = "成功") -> dict:
    return {"code": 200, "msg": msg, "data": data or {}}


def resp_error(msg: str = "失败") -> dict:
    return {"code": 500, "msg": msg, "data": {}}
