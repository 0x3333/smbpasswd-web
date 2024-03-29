function getUrlQuery() {
    return window.location.href.indexOf('?') > -1 ? window.location.href.slice(window.location.href.indexOf('?') + 1) : "";
}

function populateUsername(token) {
    function fail() {
        $("input,button").prop("disabled", true);
        swal({
            type: 'error',
            title: 'Oops...',
            html: 'Invalid authentication token! <br />Contact your System Administrator.'
        });
    }

    $.ajax({
        url: "api/get_username",
        type: "POST",
        data: JSON.stringify({ "token": token }),
        contentType: "application/json; charset=UTF-8",
        processData: false,
        dataType: "json"
    }).done(function (data) {
        if (data && typeof data === "object" && data.hasOwnProperty("username")) {
            $("#username").val(data["username"]);
        } else {
            fail();
        }
    }).fail(function (data) {
        fail();
    });
}

(function () {
    var query = getUrlQuery();

    var check = function () {
        var equal = $("#password-check").val() == $("#password").val();
        $("#password-check-icon").attr('class', equal ? "fa fa-lock text-success" : "fa fa-unlock-alt text-danger");
        $("#password-check-msg").text(equal ? "OK" : "Mismatch").attr("class", "input-group-text text-" + (equal ? "success" : "danger"));
        $("#btn-submit").prop("disabled", !equal);
    };

    function fail() {
        $("input,button").prop("disabled", true);
        swal({
            type: 'error',
            title: 'Oops...',
            html: "Couldn't change user's password. <br />Contact your System Administrator."
        })
    }

    $("#btn-submit").click(function () {
        $.ajax({
            url: "api/set_password",
            type: "POST",
            data: JSON.stringify({ "token": query, "password": $("#password-check").val() }),
            contentType: "application/json; charset=UTF-8",
            processData: false,
            dataType: "json"
        }).done(function (data) {
            if (data && typeof data === "object" &&
                data.hasOwnProperty("status") && data["status"] == "OK") {
                $("#username,#password,#password-check").val("").prop("disabled", true);
                $("#btn-submit").prop("disabled", true);
                swal({
                    type: 'success',
                    title: 'Done',
                    text: "User's password changed!"
                });
            } else {
                fail();
            }
        }).fail(function (data) {
            fail();
        });
    });

    $("#password").on("keypress keyup keydown change", function () {
        var color = "", index = 0, msg = "";

        var pass = $(this).val();
        if(pass) {
            var score = zxcvbn(pass).score;

                 if (score == 0)              { color = "text-danger"; index = 0; msg = "Very weak"; }
            else if (score > 0 && score <= 1) { color = "text-warning"; index = 1; msg = "Weak"; }
            else if (score > 1 && score <= 2) { color = "text-info"; index = 2; msg = "Fair"; }
            else if (score > 2 && score <= 3) { color = "text-primary"; index = 3; msg = "Good"; }
            else if (score > 3)               { color = "text-success"; index = 4; msg = "Strong"; }
            else                              { color = ""; index = 0; msg = ""; }
        }

        $("#thermometer").attr('class', "fa fa-thermometer-" + index + " " + color);
        $("#thermometer-msg").text(msg).attr("class", "input-group-text " + color);
        check();
    });
    $("#password-check").on("keypress keyup keydown change", check);

    $("#thermometer").attr('class', "fa fa-thermometer-0 text-danger");
    $("#thermometer-msg").text("").attr("class", "input-group-text text-danger");
    $("#password-check-icon").attr('class', "fa fa-lock text-success");
    $("#password-check-msg").attr("class", "input-group-text text-success").text("OK");

    if (query.length > 0)
        populateUsername(query);
    else {
        $("input,button").prop("disabled", true);
        swal({
            type: 'error',
            title: 'Oops...',
            html: 'Invalid user. <br />Contact your System Administrator.'
        })
    }
    $("#password").focus();
})();
