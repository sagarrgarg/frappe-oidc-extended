// Copyright (c) 2023, Mohammed Noureldin and contributors
// For license information, please see license.txt

frappe.ui.form.on('OIDC Extended Configuration', {
    setup: function(frm) {
        // No custom filter needed for Role Profiles right now
    },

    refresh: function(frm) {
        if (frm.is_new()) {
            return;
        }

        frm.add_custom_button(__('Fetch Groups From Provider'), function() {
            fetch_groups(frm);
        });
    }
});

// Reads the group names the identity provider uses and adds the missing ones to both
// mapping tables, with the profile left blank. The names are typed by hand otherwise,
// against a list that lives in another system, and a typo is silent until somebody
// logs in with no roles.
function fetch_groups(frm) {
    frappe.confirm(
        __('Read the groups this client has at the identity provider and add the ones that are missing below? Existing rows are never changed or removed, and an added row does nothing at login until you give it a profile.'),
        function() {
            frappe.call({
                method: 'oidc_extended.groups.fetch_groups',
                type: 'POST',
                args: { provider: frm.doc.name },
                freeze: true,
                freeze_message: __('Asking the identity provider which groups it has...'),
                callback: function(response) {
                    const result = response.message;

                    if (!result) {
                        return;
                    }

                    frm.reload_doc();
                    frappe.msgprint({
                        title: __('Groups Fetched'),
                        indicator: 'green',
                        message: [
                            __('Read {0} names from {1}.', [result.groups.length, result.source]),
                            '<ul>',
                            '<li>' + __('Role profile mappings: {0} added, {1} already mapped.', [
                                result.group_role_mappings_added,
                                result.group_role_mappings_present
                            ]) + '</li>',
                            '<li>' + __('Role grants: {0} added, {1} already mapped.', [
                                result.group_role_grants_added,
                                result.group_role_grants_present
                            ]) + '</li>',
                            '<li>' + __('Module mappings: {0} added, {1} already mapped.', [
                                result.group_module_mappings_added,
                                result.group_module_mappings_present
                            ]) + '</li>',
                            '</ul>',
                            __('An added row carries no profile or role yet, and is ignored at login until you give it one. Delete the rows in the tables you are not using.')
                        ].join('')
                    });
                }
            });
        }
    );
}
