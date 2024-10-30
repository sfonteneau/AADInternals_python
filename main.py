import logging
import argparse
import inspect
import os
from AADInternals import AADInternals

logging.getLogger("adal-python").setLevel(logging.WARN)

def main():
    # Initialize the main parser
    parser = argparse.ArgumentParser(description="Utility to interact with AADInternals.")
    
    # Basic arguments to instantiate AADInternals
    parser.add_argument("--domain", type=str, help="Domain name")
    parser.add_argument("--tenant_id", type=str, help="Azure AD tenant ID")
    parser.add_argument("--proxies", type=dict, default={}, help="Dictionary of proxies")
    parser.add_argument("--use_cache", type=bool, default=True, help="Use cache")
    parser.add_argument("--save_to_cache", type=bool, default=True, help="Save to cache")
    parser.add_argument("--cache_file", type=str, default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'last_token.json'), help="Cache file")

    # Create a subparser for each method
    subparsers = parser.add_subparsers(dest="method", help="Available methods in AADInternals")

    # Temporarily instantiate AADInternals to access its methods
    temp_aad = AADInternals(tenant_id=False, domain=False)
    
    # Create a subparser with help for each method
    for method_name, method in inspect.getmembers(temp_aad, predicate=inspect.ismethod):
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
        use_cache=args.use_cache,
        save_to_cache=args.save_to_cache,
        tenant_id=args.tenant_id,
        cache_file=args.cache_file,
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

        # Debug output
        print(f"Calling method: {args.method} with parameters: {method_params}")
        
        # Call the method with relevant parameters
        result = method(**method_params)
        print(result)
    else:
        print(f"The method '{args.method}' does not exist in AADInternals.")

if __name__ == "__main__":
    main()
