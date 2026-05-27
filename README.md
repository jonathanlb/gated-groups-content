## Installation

- Copy the contents of this directory to `wp-content/plugins/gated-groups-content`.
- From your WordPress dashboard, select "Plugins" from the left gutter.  Find the section "Gated Groups Content" and click activate.
- Now select "Settings" from WordPress dashboard left gutter.  Click on the "Gated Groups Content" submenu.
- Create a Google API Client ID and API Client Secret, enter them, click "Save Changes".
- Create a new post or page with content something like:
```
Any public welcome stuff goes here.

[group_content group=my-group@example.com]
Spill your secrets.
[/group_content]

Continue with public stuff if you like.
```