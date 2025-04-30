class Action(object):
    def execute(self, host):
        """
        Execute the action on the given host.
        This method should be overridden in subclasses to define specific actions.
        """
        raise NotImplementedError("Subclasses should implement this method.")