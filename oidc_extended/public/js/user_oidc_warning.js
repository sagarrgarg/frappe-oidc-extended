// Warns that this user's roles are managed by the identity provider, and locks the
// fields this app writes on their behalf.
//
// The fields differ by Frappe version - v15 stores a single role profile in
// `role_profile_name`, v16 holds several in the `role_profiles` table - so whichever
// exists on this site is the one locked. Locking is done with read_only rather than
// CSS: a rule injected into the document head applies to every form the user opens
// afterwards, and one that only greys a field out does not stop the value being saved.

frappe.ui.form.on("User", {
	refresh(frm) {
		if (frm.doc.name === "Administrator") return;

		// Every user carries a "frappe" social login row; anything else came from an
		// identity provider. Users who have never signed in through one are not managed
		// by this app and should be left alone.
		const managed_by_provider = (frm.doc.social_logins || []).some(
			(row) => row.provider && row.provider !== "frappe"
		);

		if (!managed_by_provider) return;

		frm.set_intro(
			__(
				"The roles and module profile of this user are set from the identity provider each time they sign in. Changes made here may be replaced at their next login."
			),
			"orange"
		);

		["role_profiles", "role_profile_name", "module_profile"].forEach((fieldname) => {
			if (frm.fields_dict[fieldname]) {
				frm.set_df_property(fieldname, "read_only", 1);
			}
		});
	},
});
