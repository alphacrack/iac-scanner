---
layout: default
title: Blog
---

# Blog

{% for post in site.posts %}
- **[{{ post.title }}]({{ site.baseurl }}{{ post.url }})** – {{ post.date | date: "%Y-%m-%d" }}
{% endfor %}
