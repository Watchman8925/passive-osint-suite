"""
Dependency Injection System for OSINT Suite
Manage cross-module dependencies and injection
"""

from typing import Dict, List

from modules import MODULE_REGISTRY


class DependencyInjector:
    """Handle dependency injection for OSINT modules"""

    def __init__(self):
        self._dependency_map = self._build_dependency_map()
        self._injection_cache = {}

    def _build_dependency_map(self) -> Dict[str, List[str]]:
        """Build map of module dependencies"""
        return {
            # Email intelligence depends on domain reconnaissance
            'emailintelligence': ['domain_recon'],

            # Web scraper might depend on other modules
            'webscraper': [],

            # IP intelligence might use domain recon for reverse lookups
            'ipintelligence': [],

            # Add more dependencies as needed
            'companyintelligence': ['domain_recon'],
            'socialmediafootprint': ['emailintelligence'],
            'passivesearchintelligence': ['webscraper', 'github_search']
        }

    def get_dependencies(self, module_name: str) -> List[str]:
        """Get list of dependencies for a module"""
        return self._dependency_map.get(module_name, [])

    def inject_dependencies(self, module_instance) -> None:
        """Inject dependencies into a module instance"""
        module_name = module_instance.__class__.__name__.lower()
        if module_name not in self._dependency_map:
            return

        dependencies = self._dependency_map[module_name]
        for dep_name in dependencies:
            if hasattr(module_instance, dep_name):
                continue  # Already has the dependency

            try:
                dep_instance = self._get_or_create_dependency(dep_name)
                setattr(module_instance, dep_name, dep_instance)
                module_instance.logger.info(f"Injected dependency: {dep_name}")
            except Exception as e:
                module_instance.logger.warning(f"Failed to inject dependency {dep_name}: {e}")

    def _get_or_create_dependency(self, dep_name: str):
        """Get or create a dependency instance"""
        if dep_name in self._injection_cache:
            return self._injection_cache[dep_name]

        # Create new instance directly
        if dep_name not in MODULE_REGISTRY:
            raise ValueError(f"Dependency '{dep_name}' not found")

        module_info = MODULE_REGISTRY[dep_name]
        instance = module_info['class']()
        self._injection_cache[dep_name] = instance
        return instance

    def resolve_circular_dependencies(self) -> Dict[str, List[str]]:
        """Detect and resolve circular dependencies"""
        # Simple cycle detection using DFS
        visited = set()
        rec_stack = set()
        cycles = []

        def dfs(node, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for dep in self.get_dependencies(node):
                if dep not in visited:
                    if dfs(dep, path):
                        return True
                elif dep in rec_stack:
                    # Found cycle
                    cycle_start = path.index(dep)
                    cycles.append(path[cycle_start:] + [dep])
                    return True

            rec_stack.remove(node)
            path.pop()
            return False

        for module in self._dependency_map:
            if module not in visited:
                dfs(module, [])

        # For now, just log cycles - in future could attempt resolution
        if cycles:
            print(f"Warning: Circular dependencies detected: {cycles}")

        return self._dependency_map

    def validate_dependencies(self) -> Dict[str, List[str]]:
        """Validate that all dependencies exist"""
        invalid_deps = {}

        for module_name, deps in self._dependency_map.items():
            missing = []
            for dep in deps:
                if dep not in MODULE_REGISTRY:
                    missing.append(dep)

            if missing:
                invalid_deps[module_name] = missing

        if invalid_deps:
            print(f"Warning: Invalid dependencies found: {invalid_deps}")

        return invalid_deps

class ModuleFactory:
    """Factory for creating modules with dependency injection"""

    def __init__(self):
        self.injector = DependencyInjector()
        self.injector.validate_dependencies()
        self.injector.resolve_circular_dependencies()

    def create_module(self, module_name: str):
        """Create a module instance with dependencies injected"""
        try:
            # Create the module instance directly (avoid recursion)
            if module_name not in MODULE_REGISTRY:
                raise ValueError(f"Module '{module_name}' not found")

            module_info = MODULE_REGISTRY[module_name]
            instance = module_info['class']()

            # Inject dependencies
            self.injector.inject_dependencies(instance)

            return instance

        except Exception as e:
            print(f"Failed to create module {module_name}: {e}")
            return None

# Global instances
dependency_injector = DependencyInjector()
module_factory = ModuleFactory()

def get_module_with_dependencies(module_name: str):
    """Get a module instance with dependencies injected"""
    return module_factory.create_module(module_name)