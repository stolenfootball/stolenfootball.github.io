
export async function renderMostRecentPosts(element) {
    const postsToRender = 5;

    const response = await fetch('../directory.json');
    const posts = await response.json();

    const toRender = Object.keys(posts).slice(Object.keys(posts).length - postsToRender).reduce((acc, key) => {
        acc.push(posts[key]);
        return acc;
    }, []);

    toRender.forEach(post => {
        const postElement = document.createElement('div');
        postElement.classList.add('post-summary');
        postElement.classList.add('jumbotron');
        postElement.classList.add('jumbotron-fluid');
        postElement.innerHTML = `
        <div class="container">
            <h3 class="display-4">${post.title}</h3>
            <p class="lead">${post.summary}</p>
            <a class="btn btn-primary btn-lg" href="${post.link}" role="button">Read More</a>
        </div>`;
        element.appendChild(postElement);
    });
}