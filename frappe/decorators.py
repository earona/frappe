import frappe


def whitelist(allow_guest=False, xss_safe=False, methods=None):
	"""
	Decorator for whitelisting a function and making it accessible via HTTP.
	Standard request will be `/api/method/[path.to.method]`

	:param allow_guest: Allow non logged-in user to access this method.
	:param methods: Allowed http method to access the method.

	Use as:

	        @frappe.whitelist()
	        def myfunc(param1, param2):
	                pass
	"""

	if not methods:
		methods = ["GET", "POST", "PUT", "DELETE"]

	def innerfn(fn):
		from frappe.utils.typing_validations import validate_argument_types

		# validate argument types only if request is present
		in_request_or_test = lambda: getattr(frappe.local, "request", None) or frappe.local.flags.in_test  # noqa: E731

		# get function from the unbound / bound method
		# this is needed because functions can be compared, but not methods
		method = None
		if hasattr(fn, "__func__"):
			method = validate_argument_types(fn, apply_condition=in_request_or_test)
			fn = method.__func__
		else:
			fn = validate_argument_types(fn, apply_condition=in_request_or_test)

		frappe.whitelisted.add(fn)
		frappe.allowed_http_methods_for_whitelisted_func[fn] = methods

		if allow_guest:
			frappe.guest_methods.add(fn)

			if xss_safe:
				frappe.xss_safe_methods.add(fn)

		return method or fn

	return innerfn
