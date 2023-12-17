import { addLargeHeaderBar } from './scripts/header-bar.js';

const headerBar = document.getElementById('header-bar');
addLargeHeaderBar(headerBar);

if (headerBar.classList.contains('blog-header')) {
    document.getElementById('blog-button').classList.add('active');
}

if (headerBar.classList.contains('home-header')) {
    document.getElementById('home-button').classList.add('active');
}
