// all javascript here is optional, the submitForm form works fine without
/*
What this script does:
  - confirm password validator needs javascript, otherwise always valid as long as not empty
  - set token with ?token query parameter
  - set custom validity messages
*/

// see https://stackoverflow.com/a/3028037
function hideOnClickOutside(element) {
    const outsideClickListener = event => {
        if (!element.contains(event.target) && isVisible(
            element)) {
            element.classList.add("hidden");
            removeClickListener()
        }
    };
    const removeClickListener = () => {
        document.removeEventListener("click", outsideClickListener)
    };
    document.addEventListener("click", outsideClickListener)
}

const isVisible = elem => !!elem && !!(elem.offsetWidth || elem.offsetHeight || elem.getClientRects().length);
// set token input to "?token=" query parameter
const urlParams = new URLSearchParams(window.location.search);
document.getElementById("token").value = urlParams.get("token");
// html5 validators
var username = document.getElementById("username");
var password = document.getElementById("password");
var passwordConfirmation = document.getElementById("passwordConfirmation");
var token = document.getElementById("token");
username.addEventListener("input", function (event) {
    if (username.validity.patternMismatch) {
        username.setCustomValidity("only allowed is a-z and 0-9 for user chars");
    } else {
        username.setCustomValidity("");
    }
});
token.addEventListener("input", function (event) {
    if (token.validity.typeMismatch) {
        token.setCustomValidity("case-sensitive, e.g: SardineImpactReport");
    } else {
        token.setCustomValidity("");
    }
});
password.addEventListener("input", function (event) {
    if (password.validity.typeMismatch) {
        password.setCustomValidity("atleast {{ pw_length }} characters long");
    } else {
        password.setCustomValidity("");
    }
});

function validatePassword() {
    if (password.value !== passwordConfirmation.value) {
        passwordConfirmation.setCustomValidity("passwords don't match");
    } else {
        passwordConfirmation.setCustomValidity("");
    }
}

password.onchange = validatePassword;
passwordConfirmation.onkeyup = validatePassword;

function showError(message, dialog) {
    document.getElementById("error_message").innerHTML = message;
    document.getElementById("error_dialog").innerHTML = dialog;
    let error = document.getElementById("error");
    error.classList.remove("hidden");
    hideOnClickOutside(error);
}

// hijack the submit button to display the json response in a neat modal
var form = document.getElementById("submitForm");
/*
function sendData() {
    let XHR = new XMLHttpRequest();
    // Bind the FormData object and the form element
    let FD = new FormData(form);
    // Define what happens on successful data submission
    XHR.addEventListener("load", function (event) {
        console.log(XHR.responseText);
        let response = JSON.parse(XHR.responseText);
        try {
            console.log(response);
        } catch (e) {
            if (e instanceof SyntaxError) {
                showError("Internal Server Error!", "Please contact the server admin about this.");
                return;
            }
        }
        if ("WRONG_SHARED_SECRET" === response.registrationState) {
            showError("Wrong shared secret!", "The entered shared secret is wrong! After a couple of wrong tries you will get blocked for a few hours!");
        } else if ("BLOCKED" === response.registrationState) {
            showError("Blocked!", "You tried too many times with that IP/Browser fingerprint. You are blocked for a few hours!");
        } else if ("INVALID_TOKEN" === response.registrationState) {
            showError("Wrong Token!", "The entered token is wrong.");
        } else if ("INVALID_USER_OR_PASS" === response.registrationState) {
            showError("Invalid username or password!", "You entered a username or password which contains not allowed characters! Usernames can exist of a-z and 0-9, passwords must be at least 3 chars long and not contain a whitespace!");
        } else if ("REGISTERED" === response.registrationState) {
            document.getElementById("welcome").innerHTML = "Welcome " + response.username;
            document.getElementById("success").classList.remove("hidden");
        } else if (response.status === 422) {
            showError("User already exists!", "The entered user is already registered.");
        }
        else {
            showError("Invalid response!", "Please contact the server admin about this.");
        }
    });
    // Define what happens in case of error
    XHR.addEventListener("error", function (event) {
        showError("Internal Server Error!", "Please contact the server admin about this.");
    });
    // Set up our request
    XHR.open("POST", "/registration");
    // The data sent is what the user provided in the form
    XHR.send(FD);
}
*/
function sendData() {
    let XHR = new XMLHttpRequest();

    // 从 form 构造 FormData
    let FD = new FormData(form);

    // 转成 application/x-www-form-urlencoded 格式
    let params = new URLSearchParams();
    for (const [key, value] of FD.entries()) {
        params.append(key, value);
    }

    XHR.addEventListener("load", function (event) {
        console.log(XHR.responseText);
        let response;
        try {
            response = JSON.parse(XHR.responseText);
            console.log(response);
        } catch (e) {
            if (e instanceof SyntaxError) {
                showError("Internal Server Error!", "Please contact the server admin about this.");
                return;
            }
        }

        if ("WRONG_SHARED_SECRET" === response.registrationState) {
            showError("Wrong shared secret!", "The entered shared secret is wrong! After a couple of wrong tries you will get blocked for a few hours!");
        } else if ("BLOCKED" === response.registrationState) {
            showError("Blocked!", "非法注册多次已被屏蔽");
        } else if ("INVALID_TOKEN" === response.registrationState) {
            showError("Wrong Token!", "The entered token is wrong.");
        } else if ("INVALID_USER_OR_PASS" === response.registrationState) {
            showError("Invalid username or password!", "You entered a username or password which contains not allowed characters! Usernames can exist of a-z and 0-9, passwords must be at least 3 chars long and not contain a whitespace!");
        } else if ("REGISTERED" === response.registrationState) {
            document.getElementById("welcome").innerHTML = "Welcome " + response.username;
            document.getElementById("success").classList.remove("hidden");
        } else if (response.status === 422) {
            showError("User already exists!", "The entered user is already registered.");
        } else {
            showError("Invalid response!", "Please contact the server admin about this.");
        }
    });

    XHR.addEventListener("error", function (event) {
        showError("Internal Server Error!", "Please contact the server admin about this.");
    });

    XHR.open("POST", "/registration");

    // **关键：手动设 Content-Type 为 application/x-www-form-urlencoded**
    XHR.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

    // 发送 URL 编码后的字符串
    XHR.send(params.toString());
}

// take over its submit event.
form.addEventListener("submit", function (event) {
    event.preventDefault();
    sendData();
});

function cleanForMatrix(strInput) {

    let re = /[^0-9a-z.=_/-]/g

    strInput.value = strInput.value.toLowerCase()
        .replaceAll(/\u00e4/g, "ae")
        .replaceAll(/\u00fc/g, "ue")
        .replaceAll(/\u00f6/g, "oe")
        .replaceAll(/\u00df/g, "ss")
    ;

    strInput.value = strInput.value.replace(re, "")
}