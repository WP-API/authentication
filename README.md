# WP REST API Authentication Project

## Goal

The goal of this project is to provide a first-party authentication workflow within WordPress that enables external clients to connect to the WordPress REST API for the purpose of retrieving, editing or creating content. As an example, the [WordPress Mobile applications](https://github.com/wordpress-mobile) should be able to use this API to connect directly to any WordPress site without relying on XMLRPC or proxying through [WordPress.com](https://wordpress.com).

## Current Effort

The REST API team is currently working on an OAuth solution based off our existing [OAuth2 plugin](https://github.com/wp-api/oauth2) with [Dynamic Client Registration](https://tools.ietf.org/html/rfc7591) support. The work is being done on the `dynamic-client-registration` [branch](https://github.com/WP-API/authentication/tree/dynamic-client-registration).

## Assumptions

Based on discussion at WCUS contributor day in November, 2019, we assume the following about how to best achieve the above goal:

- We will focus on developing & agreeing to user flows & architectural direction prior to implementing any code (distinguishing this project from other plugins in this organization)
- The user authentication flow is likely to follow OAuth 2
- The bearer token received at the end of the authentication process is likely to be a JSON Web Token (JWT)
- Authentication will require SSL

## Process

We will use [this GitHub Projects board](https://github.com/WP-API/authentication/projects/1?add_cards_query=is%3Aopen) to coordinate initial brainstorming and development. Tasks and to-do's should be created as [issues](
http://github.com/wp-api/authentication/issues), which will then be assigned and reviewed during weekly Slack meetings (see below).

This repository's [wiki](https://github.com/WP-API/authentication/wiki) may used as a brainstorming ground at any time, but once decisions, diagrams or architectural plans are agreed upon, they should be copied into versioned Markdown files within this repository. The wiki is currently accessible to any logged-in GitHub user, and should be regarded as a scratchpad for brainstorming rather than a long-term place for information storage.

## Meetings

We will check in on progress weekly during the scheduled REST API meeting, which occurs at **1800 UTC on Thursdays** in the **`#core-restapi`** channel within the WordPress Core Slack instance. Visit [chat.wordpress.org](https://make.wordpress.org/chat/) for access.

## Participation

We (the REST API component maintainer team, representatives from the WordPress Mobile team, and various other contributors from the WordPress community) welcome participation from anybody interested in making this project a reality. To get involved, join the WordPress slack and introduce yourself at our weekly meetings, or jump in and file or comment on an issue.
