using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;

namespace AD_Map_Backend.Hubs
{
    public class ADHub : Hub
    {
        public async Task JoinGroup(string groupName)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
        }

        public async Task LeaveGroup(string groupName)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
        }

        public async Task SubscribeToUpdates()
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, "DataUpdates");
        }

        public async Task UnsubscribeFromUpdates()
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, "DataUpdates");
        }

        /// <summary>Subscribe to real-time alert notifications from Invoke-DailyAlert.ps1 runs.</summary>
        public async Task SubscribeToAlerts()
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, "AlertSubscribers");
        }

        /// <summary>Unsubscribe from alert notifications.</summary>
        public async Task UnsubscribeFromAlerts()
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, "AlertSubscribers");
        }

        public override async Task OnConnectedAsync()
        {
            await base.OnConnectedAsync();
            await Clients.Caller.SendAsync("Connected", Context.ConnectionId);
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            await base.OnDisconnectedAsync(exception);
        }
    }
}
