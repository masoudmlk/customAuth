In this project, I implement a token-based authentication in django. In this package every user can have multiple active token for using in authentication. It can get a token for every login. It also support send OTP message for change password when users forget password or for validation their phone number.
the token does not have any limitation time for being valid but when user log out from system the token will be invalid and when user use change password, or forget password, all active tokens will become invalid.
as I said before, for forgetting password and active phone number we use OTP code, each OTP code will be valid for about four minutes and we use cache to store OTP code. we also implement a API call for different SMS service that handle base on the phone number type.

In generall, I Implement a API with 9 route contain below actions.
register user
login user
logout user
send otp code
validate otp code
change password
forget password
list tokens
kill tokens

In the register action, user should enter uesrname, password, repeat password and phone number as input and if the data that user entered was valid user can access to authentication token.
In the login action, user can access to website via username and passsword.
when the user logout the website the auth token will be removed from database.
user also can send otp code via phone for use forget password and validation phone number.
via change password, user can change password with pervious password, new password, and repeat new password and after that, all authentication token will be unvalid and user get a new valid token.

user also can see all valid tokens and kill some or all of them.
