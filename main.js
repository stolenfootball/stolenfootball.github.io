import { addLargeHeaderBar, addSmallHeaderBar } from './scripts/header-bar.js';

const headerBar = document.getElementById('header-bar');

window.innerWidth < 1100 ? addSmallHeaderBar(headerBar) : addLargeHeaderBar(headerBar);
window.addEventListener('resize', () => {
    document.getElementById('header-dynamic').remove();
    window.innerWidth < 1100 ? addSmallHeaderBar(headerBar) : addLargeHeaderBar(headerBar);
});

if (headerBar.classList.contains('blog-header')) {
    document.getElementById('blog-button').classList.add('active');
}

if (headerBar.classList.contains('home-header')) {
    document.getElementById('home-button').classList.add('active');
}
