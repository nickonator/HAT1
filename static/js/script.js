// Disable submit button on form submission
function disableButton() {
    document.getElementById("submitBTN").disabled = true;
}

// Check for cookies
function Get_Cookie(name) {
    var start = document.cookie.indexOf(name + "=");
    if (start === -1) return null;
    var len = start + name.length + 1;
    var end = document.cookie.indexOf(";", len);
    if (end === -1) end = document.cookie.length;
    return decodeURIComponent(document.cookie.substring(len, end));
}

function cookiecheck() {
    var cookietest = Get_Cookie('access_token_cookie');
    if (cookietest == null || cookietest.trim() === "") {
        document.getElementById("nocookie").style.display = "block";
        document.getElementById("cookie").style.display = "none";
    } else {
        document.getElementById("nocookie").style.display = "none";
        document.getElementById("cookie").style.display = "block";
    }
}

// Toggle sidebar
function toggleSidebar() {
    var sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle('active');
}

// Apply theme settings
function applySettings() {
    if (localStorage.getItem("lightMode") === "enabled") {
        document.body.classList.add("light-modestorage");
        document.body.classList.remove("dark-modestorage");
    } else {
        document.body.classList.add("dark-modestorage");
        document.body.classList.remove("light-modestorage");
    }
}

// Event listeners
document.addEventListener("DOMContentLoaded", function () {
    cookiecheck(); // Check cookies on page load
    applySettings(); // Apply theme settings on page load

    // Toggle light/dark mode
    const lightModeToggle = document.getElementById("toggle-light-mode");
    if (lightModeToggle) {
        lightModeToggle.addEventListener("click", function () {
            if (document.body.classList.contains("light-modestorage")) {
                document.body.classList.remove("light-modestorage");
                document.body.classList.add("dark-modestorage");
                localStorage.setItem("darkMode", "enabled");
                localStorage.removeItem("lightMode");
            } else {
                document.body.classList.remove("dark-modestorage");
                document.body.classList.add("light-modestorage");
                localStorage.setItem("lightMode", "enabled");
                localStorage.removeItem("darkMode");
            }
        });
    }

    // Listen for changes in localStorage
    window.addEventListener("storage", function (event) {
        if (event.key === "lightMode" || event.key === "darkMode") {
            console.log("localStorage change detected. Updating theme...");
            applySettings(); // Reapply the theme
        }
    });
});