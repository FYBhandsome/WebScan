from utils.tools import resp_success, resp_error


class TestTools:
    def test_resp_success_default(self):
        result = resp_success()
        assert result["code"] == 200
        assert result["msg"] == "成功"
        assert result["data"] == {}

    def test_resp_success_with_data(self):
        result = resp_success({"id": 1}, "操作成功")
        assert result["code"] == 200
        assert result["msg"] == "操作成功"
        assert result["data"] == {"id": 1}

    def test_resp_error_default(self):
        result = resp_error()
        assert result["code"] == 500
        assert result["msg"] == "失败"
        assert result["data"] == {}

    def test_resp_error_custom_msg(self):
        result = resp_error("任务不存在")
        assert result["code"] == 500
        assert result["msg"] == "任务不存在"
        assert result["data"] == {}
