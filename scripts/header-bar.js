

export function addLargeHeaderBar(element) {
    const oldHeader = element.innerHTML;
    element.innerHTML = `
    <div id="header-dynamic" class="row">
        <div class="col-sm-1 header-item"></div>
        <div class="col-sm-8 header-item">
            <nav class="navbar navbar-default header-item">
                <div class="container-fluid">
                    <div class="navbar-header">
                        <a class="navbar-brand" href="./index.html">stolenfootball.dev</a>
                    </div>
                    <ul class="nav navbar-nav">
                        <li id="home-button"><a href="./index.html">Home</a></li>
                        <li id="blog-button"><a href="./blog.html">Blog</a></li>
                        <li id="about-button"><a href='#'>About</a></li>
                        <li id="contact-button"><a href='#'>Contact</a></li>
                    </ul>
                </div>
            </nav>
        </div>
        <div class="col-sm-2 header-item">
            <div id="header-right" style="height: 100%">
                <a href="https://www.linkedin.com/in/jeremy-dunn-a0b945172/"><i class="fa fa-linkedin-square social-icon" style="font-size:36px;color:black"></i></a> 
                <a href="https://github.com/stolenfootball"><i class="fa fa-github-square social-icon" style="font-size:36px;color:black"></i></a>
                <a href="mailto:jeremy.dunn315@gmail.com"><i class="fa fa-envelope-square social-icon" style="font-size:36px;color:black"></i></a>
            </div>
        </div>
        <div class="col-sm-1 header-item"></div>
    </div>
    ` + oldHeader;
}


export function addSmallHeaderBar(element) {
    const oldHeader = element.innerHTML;
    element.innerHTML = `
    <div id="header-dynamic" class="row">
        <div class="col header-item">
            <nav class="navbar navbar-default header-item">
                <div class="dropdown">
                    <a class="navbar-brand dropdown-toggle" data-toggle="dropdown" href="#">stolenfootball.dev
                    <span class="caret"></span></a>
                    <ul class="dropdown-menu">
                        <li id="home-button"><a href="./index.html">Home</a></li>
                        <li id="blog-button"><a href="./blog.html">Blog</a></li>
                        <li id="about-button"><a href='#'>About</a></li>
                        <li id="contact-button"><a href='#'>Contact</a></li>
                    </ul>
                </div>
            </nav>
        </div>
    </div>` + oldHeader;
}