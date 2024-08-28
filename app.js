document.getElementById('suggestion-form').addEventListener('submit', async function(event) {
    event.preventDefault(); // Prevent the default form submission behavior

    const topic = document.getElementById('topic-input').value;

    try {
        const response = await fetch('/suggest', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ topic })  // Send the user's input to the backend
        });

        const data = await response.json();
        console.log(data); // Handle the data from the backend (e.g., display it on the page)
    } catch (error) {
        console.error('Error fetching suggestions:', error);
    }
});
