function getUrlQuery() {
    return window.location.href.indexOf('?') > -1 ? window.location.href.slice(window.location.href.indexOf('?') + 1) : "";
}
function scorePassword(pass) {
    var score = 0;
    if (!pass)
        return score;

    // award every unique letter until 5 repetitions
    var letters = new Object();
    for (var i = 0; i < pass.length; i++) {
        letters[pass[i]] = (letters[pass[i]] || 0) + 1;
        score += 5.0 / letters[pass[i]];
    }

    // bonus points for mixing it up
    var variations = {
        digits: /\d/.test(pass),
        lower: /[a-z]/.test(pass),
        upper: /[A-Z]/.test(pass),
        nonWords: /\W/.test(pass),
    }

    variationCount = 0;
    for (var check in variations) {
        variationCount += (variations[check] == true) ? 1 : 0;
    }
    score += (variationCount - 1) * 10;

    score += pass.length < 6 ? -10 : 0;
    return Math.max(0, parseInt(score));
}

function checkPassStrength(pass) {
    var score = scorePassword(pass);
    if (score > 80)
        return "strong";
    if (score > 60)
        return "good";
    if (score >= 30)
        return "weak";

    return "";
}

function populateUsername(token) {
    $.ajax("api/get_username/" + token)
        .done(function(data) {
            $("#username").val(data);
        })
        .fail(function(data) {
            $("input,button").prop("disabled", true);
            swal({
                type: 'error',
                title: 'Oops...',
                html: 'Invalid authentication token! <br />Contact your System Administrator.'
            })
        });
}

(function() {
    var query = getUrlQuery();

    var check = function() {
        var equal = $("#password-check").val() == $("#password").val();
        $("#password-check-icon").attr('class', equal ? "fa fa-lock text-success" : "fa fa-unlock-alt text-danger");
        $("#password-check-msg").text(equal ? "OK" : "Mismatch").attr("class", "input-group-text text-" + (equal ? "success" : "danger"));
        $("#btn-submit").prop("disabled", !equal);
    };

    $("#btn-submit").click(function() {
        $.ajax("api/set_password/" + query + "/" + $("#password-check").val())
        .done(function(data) {
            $("#username,#password,#password-check").val("").prop("disabled", true);
            $("#btn-submit").prop("disabled", true);
            swal({
                type: 'success',
                title: 'Done',
                text: "User's password changed!"
            })

        })
        .fail(function(data) {
            $("input,button").prop("disabled", true);
            swal({
                type: 'error',
                title: 'Oops...',
                html: "Couldn't change user's password. <br />Contact your System Administrator."
            })
        });
    });

    $("#password").on("keypress keyup keydown change", function() {
        var pass = $(this).val();
        var score = scorePassword(pass);
        var color, index, msg;

        if (score <= 30) { color = "text-danger"; index = 0; msg = "Very weak"; }
        if (score > 30 && score <= 45) { color = "text-warning"; index = 1; msg = "Weak"; }
        if (score > 45 && score <= 60) { color = "text-info"; index = 2; msg = "Fair"; }
        if (score > 60 && score <= 80) { color = "text-primary"; index = 3; msg = "Good"; }
        if (score > 80) { color = "text-success"; index = 4; msg = "Strong"; }

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
