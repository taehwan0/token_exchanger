## Authorization Code Flow

### 1. Authorization 요청 보내기

```text
http://localhost:9000/oauth2/authorize?response_type=code&client_id=oidc-client&redirect_uri=http://localhost:8080/login/oauth2/code/oidc-client&scope=openid%20profile
```

위 url로 접근, queryString에 대한 값들은 설정에 따라 바뀔 수 있음.  
`application.yml`에 기본으로 설정된 값들에 맞춰 진행한다.

### 2. 사용자 로그인

아래의 정보를 통해서 form을 통해 로그인한다.

- **username: user**
- **password: password**

### 3. Authorization Code 응답 받기

```text
http://localhost:8080/login/oauth2/code/oidc-client?code=WVmjHGToI9RH7D1VxbdNqGBGa-jnGBjYUa1QqCG_qR0RdYc6TOqVkW0_NFXelDk5PyzTBnoMjy_fThMtW2aBIK_Wsv5A6ORE_FGd1cTaHPt4Wv8U26lpB-U3knOsy2C1
```

위와 같은 url로 redirect된다.

### 4. Authorization Code를 Token으로 교환하기

3에서 받은 `authorization_code`를 넣어 아래와 같이 요청을 보낸다.

```shell
curl -X POST http://localhost:9000/oauth2/token \
  -H "Authorization: Basic b2lkYy1jbGllbnQ6c2VjcmV0" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code={authroization_code}&redirect_uri=http://localhost:8080/login/oauth2/code/oidc-client"
```

아래와 같은 response를 받는다.

```json
{
  "access_token": "eyJraWQiOiJkODEyYzg3Ni04NTE2LTRjYWItYmMzZS1mNTE2M2FhZDY1NDMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MTk3Mzk4NTUsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNzE5NzQwMTU1LCJpYXQiOjE3MTk3Mzk4NTUsImp0aSI6IjliNzViYWM5LWU2ZmEtNGU3YS04YmYxLTBjZDcxMzgwNTkwZSJ9.TNZbFjkuFLtwghVfXakuJaVB2WfNlBpYEPiNGryA5ve1d-33Z2cGT_700AMjXmo-3etxjHLW3xU-krLq0kbheYhP8r5uP-2b1BHTgxqCVv8jz3E45Ljilz7jK9OBE3P8O-Pyp5e6iLNKb6fWWS9wvEee4fiIZ91LfJ5hGhbMROvj7X-ehFijTiHoSNZUTFre0FFlrS4Ee1vGHfRXQcLIciUhSuSgt3YsNq8tbzwh2_cN32UGll5U_guLtDJWKNIbeiaLi3Lvm1mB2LvmQL2eS-eY0aDGRJ8IgiAL7N-Ku7CE-7bhISPI6necGI5tv0G9hjLRpJ3X79o02jTeuuSVtw",
  "refresh_token": "Sr0WG25gquPnBhfRbeoKYqQkyLmNolWHJD5fe50u2A5nIT0jcL3NSk1giBGBTbcWytMSFQI-9cZqvlyVXVoB9UVYXKNYdJABQatArSHbRPuTvMvlXBu8XNz7aj9iQrfU",
  "scope": "openid profile",
  "id_token": "eyJraWQiOiJkODEyYzg3Ni04NTE2LTRjYWItYmMzZS1mNTE2M2FhZDY1NDMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJhenAiOiJvaWRjLWNsaWVudCIsImF1dGhfdGltZSI6MTcxOTczOTI3OCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNzE5NzQxNjU1LCJpYXQiOjE3MTk3Mzk4NTUsImp0aSI6IjMzMWVmMWVhLTY3MmItNGE4OC1iMDdiLTQ2MzM4YzM1ZjJmYSIsInNpZCI6Ik52bk16OFVtcmRyUlRYcXlaeUdkOUowYnlSaEREQ2tUdVlpYll6a3RaS2cifQ.eKHDU23QNIntNdd0mIkWrs-TjXlWvTV0lAjZ6DxpmY7D8d_mnwdrvsY70cc1RwbYbIWvrr2ITheoQz5rd2AKz0N6HNGYsiEa1zh-0cJ5TQpvYKLQ-GfwI7lYvvTyndxZvgyxGSpwaDyzWzmALQVoKMBrKc8no9oRy5WnKEVQckbgwS-DYcvXIA9icXabCKa9gJXArQWVH-aTS9hiUz4Sd7jWIVdZD7_YrJWP7B2YaADEM2YXIN8RcLOov1bmlbYesCY_gv9yq60pxt2hB4ZS7Os0cVE7meePAcBF4IMmqjviprcjlSAbx54qYqMktbSPr-V9uw26t4H2PTL-zaPV2Q",
  "token_type": "Bearer",
  "expires_in": 299
}
```