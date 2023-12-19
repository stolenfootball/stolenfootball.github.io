import { renderMostRecentPosts } from './post-summaries.js';

const postSummaries = document.getElementById('recent-posts');
renderMostRecentPosts(postSummaries, 10);