import { useNavigate } from '@solidjs/router';
import type { Component } from 'solid-js';
import { createEffect, createSignal, For, Show } from 'solid-js';

import type { User } from '../api/user';
import { userApi } from '../api/user';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';

import { Spinner } from './ui/spinner';

export const AssociatedAccounts: Component = () => {
  const [users, setUsers] = createSignal<User[]>([]);
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const navigate = useNavigate();

  createEffect(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await userApi.getUsersWithCurrentLogin();
      setUsers(data);
    }
    catch (err) {
      setError(err instanceof Error
        ? err.message
        : 'Failed to load associated accounts');
      console.error('Error fetching associated accounts:', err);
    }
    finally {
      setIsLoading(false);
    }
  });

  const handleSwitchUser = async (userId: string) => {
    try {
      const response = await userApi.switchUser(userId);
      // No need to display response details as per requirements
      // Just check if the switch was successful
      if (response && response.status === 'success') {
        // After switching user, redirect to homepage
        navigate('/');
      }
      else {
        setError('Failed to switch user');
      }
    }
    catch (err) {
      setError(err instanceof Error
        ? err.message
        : 'Failed to switch user');
      console.error('Error switching user:', err);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Associated Accounts</CardTitle>
      </CardHeader>
      <CardContent>
        <Show
          when={isLoading()}
        >
          <div
            class="flex justify-center py-4"
          >
            <Spinner />
          </div>
        </Show>

        <Show
          when={error()}
        >
          <div
            class="text-red-500 mb-4"
          >
            {error()}
          </div>
        </Show>

        <Show
          when={!isLoading() && !error() && users().length === 0}
        >
          <p
            class="text-sm text-gray-600"
          >
            No associated accounts found.
          </p>
        </Show>

        <Show
          when={!isLoading() && users().length > 0}
        >
          <div
            class="space-y-4"
          >
            <p
              class="text-sm text-gray-600 mb-2"
            >
              These accounts are associated with your current login. You can switch between them without re-authenticating.
            </p>
            <div
              class="space-y-2"
            >
              <For
                each={users()}
              >
                {user => (
                  <div
                    class="flex items-center justify-between p-3 border rounded-md"
                  >
                    <div>
                      <div
                        class="font-medium"
                      >
                        {user.name || user.username}
                      </div>
                      <div
                        class="text-sm text-gray-500"
                      >
                        {user.email}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleSwitchUser(user.id!)}
                    >
                      Switch
                    </Button>
                  </div>
                )}
              </For>
            </div>
          </div>
        </Show>
      </CardContent>
    </Card>
  );
};

export default AssociatedAccounts;
