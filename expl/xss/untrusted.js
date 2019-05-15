document.getElementById("a").innerHTML =
    '<img onerror=\'(function () { document.getElementById("b").innerHTML = "The exploit has been executed"; })()\' src="/static/notanimage.jpg" />';
