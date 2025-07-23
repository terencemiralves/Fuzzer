import os
import resource
import contextlib

@contextlib.contextmanager
def enable_core_dumps(path="/tmp"):
    # Save the current working directory and resource limits
    old_cwd = os.getcwd()
    old_limits = resource.getrlimit(resource.RLIMIT_CORE)

    try:
        # Apply the changes
        os.chdir(path)
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        yield
    finally:
        # Restore the original working directory and resource limits
        os.chdir(old_cwd)
        resource.setrlimit(resource.RLIMIT_CORE, old_limits)

