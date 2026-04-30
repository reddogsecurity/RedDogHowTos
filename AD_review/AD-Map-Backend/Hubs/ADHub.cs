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
