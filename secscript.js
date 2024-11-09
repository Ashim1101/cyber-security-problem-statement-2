// JavaScript to show more details about features
function showDetails(feature) {
    if (feature === 'rogue-detection') {
        alert('Rogue Access Point Detection: This system scans the network to identify unauthorized access points that might attempt to intercept or manipulate data.');
    } else if (feature === 'traffic-analysis') {
        alert('Traffic Analysis: The system monitors network traffic for unusual patterns or potential threats, preventing data interception or malware infections.');
    }
}

// Form submission handler (you can add your backend integration here)
document.getElementById('contact-form').addEventListener('submit', function(event) {
    event.preventDefault();
    alert('Thank You for your Response,Your message has been submitted. We will get back to you soon!');
});
