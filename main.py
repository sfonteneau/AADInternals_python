import logging
import argparse
import inspect
from AADInternals import AADInternals

logging.getLogger("adal-python").setLevel(logging.WARN)

def main():
    # Initialize the main parser
    parser = argparse.ArgumentParser(description="Utility to interact with AADInternals.")
    
    # Basic arguments to instantiate AADInternals
    parser.add_argument("--domain", type=str, help="Domain name")
    parser.add_argument("--tenant_id", type=str, help="Azure AD tenant ID")
    parser.add_argument("--proxies", type=dict, default={}, help="Dictionary of proxies")
    parser.add_argument("--entra_aba_dir", type=str, default="/root/entra_aba", help="PFX identity directory (default: /root/entra_aba)")

    # Create a subparser for each method
    subparsers = parser.add_subparsers(dest="method", help="Available methods in AADInternals")

    # Temporarily instantiate AADInternals to access its methods
    temp_aad = AADInternals(tenant_id=False, domain=False)
    
    # Create a subparser with help for each method
    for method_name, method in inspect.getmembers(temp_aad, predicate=inspect.ismethod):
        if method_name.startswith("_"):
            continue
        method_parser = subparsers.add_parser(method_name, help=f"Help for {method_name}")

        # Add specific arguments for each method
        for param_name, param in inspect.signature(method).parameters.items():
            if param_name != "self":  # Exclude 'self'
                # Add the parameter to the parser
                method_parser.add_argument(f"--{param_name}", help=f"Argument for {method_name}")

    # Parse all arguments
    args = parser.parse_args()

    # Initialize AADInternals with the base arguments
    aad = AADInternals(
        proxies=args.proxies,
        tenant_id=args.tenant_id,
        entra_aba_dir=args.entra_aba_dir,
        domain=args.domain
    )
    
    # Check that the method exists and call it with its arguments
    if not args.method:
        parser.print_help()
    elif hasattr(aad, args.method):
        method = getattr(aad, args.method)

        # Prepare the parameters to pass to the method
        method_params = {}
        for param_name in inspect.signature(method).parameters:
            if param_name in vars(args) and vars(args)[param_name] is not None:
                method_params[param_name] = vars(args)[param_name]

        # Avoid leaking secrets in logs, CLI output or captured service output.
        print(f"Calling method: {args.method}")

        result = method(**method_params)
        if args.method == "get_token":
            print("Token acquired (not displayed)")
        else:
            print(result)
    else:
        print(f"The method '{args.method}' does not exist in AADInternals.")

if __name__ == "__main__":
    main()
