<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML RESPONSE</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" th:action="@{${ACSUrl}}" >
        <input type="hidden" name="SAMLResponse" th:value="${SAMLResponse}">
        <input type="hidden" name="RelayState" th:value="${RelayState}">
    </form>
</body>
</html>