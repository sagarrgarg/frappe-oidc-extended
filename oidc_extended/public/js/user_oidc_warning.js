// Says who decides this user's roles, and locks the fields only where the answer is
// "the identity provider".
//
// There are two ways to run this app. Where it maps groups to roles, an edit made here
// is replaced at the user's next login, so the fields it writes are locked and the form
// says why. Where it is used to sign people in and to close their accounts when they
// leave - "Use Groups From The Identity Provider" off - the roles are the ERP's, and
// locking them would stop exactly the work that mode exists for.
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
		const providers = (frm.doc.social_logins || [])
			.map((row) => row.provider)
			.filter((provider) => provider && provider !== "frappe");

		if (!providers.length) return;

		// Set by oidc_extended.boot.boot_session. Absent on a session that started
		// before the app was installed, in which case say nothing rather than guess.
		const managing = (frappe.boot.oidc_extended || {}).providers_managing_roles;

		if (!managing) return;

		const roles_come_from = providers.filter((provider) => managing.includes(provider));

		if (roles_come_from.length) {
			frm.set_intro(
				__(
					"The roles and module profile of this user are set from the identity provider ({0}) each time they sign in. Changes made here may be replaced at their next login.",
					[roles_come_from.join(", ")]
				),
				"orange"
			);

			["role_profiles", "role_profile_name", "module_profile"].forEach((fieldname) => {
				if (frm.fields_dict[fieldname]) {
					frm.set_df_property(fieldname, "read_only", 1);
				}
			});

			return;
		}

		frm.set_intro(
			__(
				"This user signs in through {0}, which does not manage roles on this site: their roles are set here and are not changed by signing in. Their account is disabled if they are removed from the directory.",
				[providers.join(", ")]
			),
			"blue"
		);
	},
});
